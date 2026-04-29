#!/usr/bin/env python
from time import sleep
import struct
import hashlib
import bz2
import sys
import argparse
import bsdiff4
import io
import os
from enlighten import get_manager
import lzma
import brotli
from multiprocessing import cpu_count
from concurrent.futures import ThreadPoolExecutor, as_completed
import payload_dumper.update_metadata_pb2 as um

flatten = lambda l: [item for sublist in l for item in sublist]


def u32(x):
    return struct.unpack(">I", x)[0]


def u64(x):
    return struct.unpack(">Q", x)[0]


def verify_contiguous(exts):
    blocks = 0
    for ext in exts:
        if ext.start_block != blocks:
            return False

        blocks += ext.num_blocks

    return True


def _parse_message(data):
    """Parse a protobuf wire-format message.
    Returns list of (field_number, wire_type, value) tuples.
    """
    result = []
    pos = 0
    while pos < len(data):
        tag_byte = data[pos]
        pos += 1
        field_number = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:  # Varint
            value = 0
            shift = 0
            while pos < len(data):
                b = data[pos]
                pos += 1
                value |= (b & 0x7f) << shift
                if not (b & 0x80):
                    break
                shift += 7
            result.append((field_number, wire_type, value))
        elif wire_type == 2:  # Length-delimited
            length = 0
            shift = 0
            while pos < len(data):
                b = data[pos]
                pos += 1
                length |= (b & 0x7f) << shift
                if not (b & 0x80):
                    break
                shift += 7
            sub_data = data[pos:pos + length]
            pos += length
            result.append((field_number, wire_type, sub_data))
        elif wire_type == 1:  # 64-bit
            value = struct.unpack('<Q', data[pos:pos + 8])[0]
            pos += 8
            result.append((field_number, wire_type, value))
        elif wire_type == 5:  # 32-bit
            value = struct.unpack('<I', data[pos:pos + 4])[0]
            pos += 4
            result.append((field_number, wire_type, value))
        else:
            break
    return result


class Dumper:
    def __init__(
        self, payloadfile, out, diff=None, old=None, images="", workers=cpu_count()
    ):
        self.payloadfile = payloadfile
        self.out = out
        self.diff = diff
        self.old = old
        self.images = images
        self.workers = workers
        self.validate_magic()
        self.manager = get_manager()

    def run(self):
        if self.images == "":
            partitions = self.dam.partitions
        else:
            partitions = []
            for image in self.images.split(","):
                image = image.strip()
                found = False
                for dam_part in self.dam.partitions:
                    if dam_part.partition_name == image:
                        partitions.append(dam_part)
                        found = True
                        break
                if not found:
                    print("Partition %s not found in image" % image)

        if len(partitions) == 0:
            print("Not operating on any partitions")
            return 0

        partitions_with_ops = []
        for partition in partitions:
            operations = []
            for operation in partition.operations:
                self.payloadfile.seek(self.data_offset + operation.data_offset)
                operations.append(
                    {
                        "operation": operation,
                        "data": self.payloadfile.read(operation.data_length),
                    }
                )
            partitions_with_ops.append(
                {
                    "partition": partition,
                    "operations": operations,
                }
            )

        self.payloadfile.close()

        self.multiprocess_partitions(partitions_with_ops)
        self.manager.stop()

    def multiprocess_partitions(self, partitions):
        progress_bars = {}

        def update_progress(partition_name, count):
            progress_bars[partition_name].update(count)

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            for part in partitions:
                partition_name = part['partition'].partition_name
                progress_bars[partition_name] = self.manager.counter(
                    total=len(part["operations"]),
                    desc=f"{partition_name}",
                    unit="ops",
                    leave=True,
                )

            futures = {executor.submit(self.dump_part, part, update_progress): part for part in partitions}

            for future in as_completed(futures):
                part = futures[future]
                partition_name = part['partition'].partition_name
                try:
                    future.result()
                    progress_bars[partition_name].close()
                except Exception as exc:
                    print(f"{partition_name} - processing generated an exception: {exc}")
                    progress_bars[partition_name].close()


    def validate_magic(self):
        magic = self.payloadfile.read(4)
        assert magic == b"CrAU"

        file_format_version = u64(self.payloadfile.read(8))
        assert file_format_version == 2

        manifest_size = u64(self.payloadfile.read(8))

        metadata_signature_size = 0

        if file_format_version > 1:
            metadata_signature_size = u32(self.payloadfile.read(4))

        manifest = self.payloadfile.read(manifest_size)
        self.metadata_signature = self.payloadfile.read(metadata_signature_size)
        self.data_offset = self.payloadfile.tell()

        self.dam = um.DeltaArchiveManifest()
        self.dam.ParseFromString(manifest)
        self.block_size = self.dam.block_size

    def data_for_op(self, operation, out_file, old_file):
        data = operation["data"]
        op = operation["operation"]

        # assert hashlib.sha256(data).digest() == op.data_sha256_hash, 'operation data hash mismatch'

        if op.type == op.REPLACE_XZ:
            dec = lzma.LZMADecompressor()
            data = dec.decompress(data)
            out_file.seek(op.dst_extents[0].start_block * self.block_size)
            out_file.write(data)
        elif op.type == op.REPLACE_BZ:
            dec = bz2.BZ2Decompressor()
            data = dec.decompress(data)
            out_file.seek(op.dst_extents[0].start_block * self.block_size)
            out_file.write(data)
        elif op.type == op.REPLACE:
            out_file.seek(op.dst_extents[0].start_block * self.block_size)
            out_file.write(data)
        elif op.type == op.SOURCE_COPY:
            if not self.diff:
                print("SOURCE_COPY supported only for differential OTA")
                sys.exit(-2)
            out_file.seek(op.dst_extents[0].start_block * self.block_size)
            for ext in op.src_extents:
                old_file.seek(ext.start_block * self.block_size)
                data = old_file.read(ext.num_blocks * self.block_size)
                out_file.write(data)
        elif op.type == op.SOURCE_BSDIFF:
            if not self.diff:
                print("SOURCE_BSDIFF supported only for differential OTA")
                sys.exit(-3)
            out_file.seek(op.dst_extents[0].start_block * self.block_size)
            tmp_buff = io.BytesIO()
            for ext in op.src_extents:
                old_file.seek(ext.start_block * self.block_size)
                old_data = old_file.read(ext.num_blocks * self.block_size)
                tmp_buff.write(old_data)
            tmp_buff.seek(0)
            old_data = tmp_buff.read()
            tmp_buff.seek(0)
            tmp_buff.write(bsdiff4.patch(old_data, data))
            n = 0
            tmp_buff.seek(0)
            for ext in op.dst_extents:
                tmp_buff.seek(n * self.block_size)
                n += ext.num_blocks
                data = tmp_buff.read(ext.num_blocks * self.block_size)
                out_file.seek(ext.start_block * self.block_size)
                out_file.write(data)
        elif op.type == op.BROTLI_BSDIFF:
            if not self.diff:
                print("BROTLI_BSDIFF supported only for differential OTA")
                sys.exit(-3)
            # BSDF2 format: magic(5) + flags(3) + ctrl_len(8) + diff_len(8) + new_size(8)
            # data[5]: format version (1 or 2) — controls ctrl compression
            #   v1: ctrl=bzip2
            #   v2: ctrl=brotli
            # data[6]: diff compression (0x01=bzip2, 0x02=brotli)
            # data[7]: extra compression (0x01=bzip2, 0x02=brotli)
            bsdf2_ver = data[5]
            diff_comp = data[6]   # 0x01=bzip2, 0x02=brotli
            extra_comp = data[7]  # 0x01=bzip2, 0x02=brotli
            ctrl_len = struct.unpack('<Q', data[8:16])[0]
            diff_len = struct.unpack('<Q', data[16:24])[0]
            new_size = struct.unpack('<Q', data[24:32])[0]
            HDR = 32
            ctrl_raw = data[HDR:HDR+ctrl_len]
            diff_raw = data[HDR+ctrl_len:HDR+ctrl_len+diff_len]
            extra_raw = data[HDR+ctrl_len+diff_len:]

            # Decompress ctrl based on format version
            if ctrl_raw:
                if bsdf2_ver >= 2:
                    ctrl_dec = brotli.decompress(ctrl_raw)
                else:
                    ctrl_dec = bz2.decompress(ctrl_raw)
            else:
                ctrl_dec = b''

            # Decompress diff based on data[6] flag
            if diff_raw:
                if diff_comp == 0x01:
                    diff_dec = bz2.decompress(diff_raw)
                else:
                    diff_dec = brotli.decompress(diff_raw)
            else:
                diff_dec = b''

            # Decompress extra based on data[7] flag
            if extra_raw:
                if extra_comp == 0x01:
                    extra_dec = bz2.decompress(extra_raw)
                else:
                    extra_dec = brotli.decompress(extra_raw)
            else:
                extra_dec = b''

            # Build BSDIFF40 patch with bzip2-compressed sections
            ctrl_bz2 = bz2.compress(ctrl_dec)
            diff_bz2 = bz2.compress(diff_dec)
            extra_bz2 = bz2.compress(extra_dec) if extra_dec else b''
            bsdiff_data = b'BSDIFF40' + struct.pack('<QQQ', len(ctrl_bz2), len(diff_bz2), new_size if new_size > 0 else len(diff_dec))
            bsdiff_data += ctrl_bz2 + diff_bz2 + extra_bz2
            # Read source data
            tmp_buff = io.BytesIO()
            for ext in op.src_extents:
                old_file.seek(ext.start_block * self.block_size)
                old_data = old_file.read(ext.num_blocks * self.block_size)
                tmp_buff.write(old_data)
            tmp_buff.seek(0)
            old_data = tmp_buff.read()
            # Apply patch and write to dst extents
            patched = bsdiff4.patch(old_data, bsdiff_data)
            n = 0
            for ext in op.dst_extents:
                chunk = patched[n * self.block_size:(n + ext.num_blocks) * self.block_size]
                n += ext.num_blocks
                out_file.seek(ext.start_block * self.block_size)
                out_file.write(chunk)
        elif op.type == op.PUFFDIFF:
            if not self.diff:
                print("PUFFDIFF supported only for differential OTA")
                sys.exit(-3)
            if data[:4] != b'PUF1':
                raise ValueError('Invalid Puffin magic')
            hdr_len = struct.unpack('>I', data[4:8])[0]
            # The payload after the Puffin header is in BSDF2 format (Qualcomm extension)
            bsdf2_data = data[8+hdr_len:]
            if bsdf2_data[:5] != b'BSDF2':
                raise ValueError('Expected BSDF2 data after Puffin header')
            # Parse BSDF2 header
            bsdf2_ver = bsdf2_data[5]
            diff_comp = bsdf2_data[6]
            extra_comp = bsdf2_data[7]
            ctrl_len = struct.unpack('<Q', bsdf2_data[8:16])[0]
            diff_len = struct.unpack('<Q', bsdf2_data[16:24])[0]
            new_size = struct.unpack('<Q', bsdf2_data[24:32])[0]
            HDR = 32
            ctrl_raw = bsdf2_data[HDR:HDR+ctrl_len]
            diff_raw = bsdf2_data[HDR+ctrl_len:HDR+ctrl_len+diff_len]
            extra_raw = bsdf2_data[HDR+ctrl_len+diff_len:]
            # Decompress ctrl
            if ctrl_raw:
                if bsdf2_ver >= 2:
                    ctrl_dec = brotli.decompress(ctrl_raw)
                else:
                    ctrl_dec = bz2.decompress(ctrl_raw)
            else:
                ctrl_dec = b''
            # Decompress diff
            if diff_raw:
                if diff_comp == 0x01:
                    diff_dec = bz2.decompress(diff_raw)
                else:
                    diff_dec = brotli.decompress(diff_raw)
            else:
                diff_dec = b''
            # Decompress extra
            if extra_raw:
                if extra_comp == 0x01:
                    extra_dec = bz2.decompress(extra_raw)
                else:
                    extra_dec = brotli.decompress(extra_raw)
            else:
                extra_dec = b''
            # Build BSDIFF40 patch
            ctrl_bz2 = bz2.compress(ctrl_dec)
            diff_bz2 = bz2.compress(diff_dec)
            extra_bz2 = bz2.compress(extra_dec) if extra_dec else b''
            bsdiff_data = b'BSDIFF40' + struct.pack('<QQQ', len(ctrl_bz2), len(diff_bz2), new_size if new_size > 0 else len(diff_dec))
            bsdiff_data += ctrl_bz2 + diff_bz2 + extra_bz2
            # Read source data
            tmp_buff = io.BytesIO()
            for ext in op.src_extents:
                old_file.seek(ext.start_block * self.block_size)
                old_data = old_file.read(ext.num_blocks * self.block_size)
                tmp_buff.write(old_data)
            tmp_buff.seek(0)
            old_data = tmp_buff.read()
            # Apply patch and write to dst extents
            patched = bsdiff4.patch(old_data, bsdiff_data)
            n = 0
            for ext in op.dst_extents:
                chunk = patched[n * self.block_size:(n + ext.num_blocks) * self.block_size]
                n += ext.num_blocks
                out_file.seek(ext.start_block * self.block_size)
                out_file.write(chunk)
        elif op.type == op.ZERO:
            for ext in op.dst_extents:
                out_file.seek(ext.start_block * self.block_size)
                out_file.write(b"\x00" * ext.num_blocks * self.block_size)
        else:
            print("Unsupported type = %d" % op.type)
            sys.exit(-1)

        return data

    def dump_part(self, part, update_callback):
        name = part["partition"].partition_name
        out_file = open("%s/%s.img" % (self.out, name), "wb")
        h = hashlib.sha256()

        if self.diff:
            old_file = open("%s/%s.img" % (self.old, name), "rb")
        else:
            old_file = None

        for op in part["operations"]:
            data = self.data_for_op(op, out_file, old_file)
            update_callback(part["partition"].partition_name, 1)


def main():
    parser = argparse.ArgumentParser(description="OTA payload dumper")
    parser.add_argument(
        "payloadfile", type=argparse.FileType("rb"), help="payload file name"
    )
    parser.add_argument(
        "--out", default="output", help="output directory (default: 'output')"
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="extract differential OTA",
    )
    parser.add_argument(
        "--old",
        default="old",
        help="directory with original images for differential OTA (default: 'old')",
    )
    parser.add_argument(
        "--partitions",
        default="",
        help="comma separated list of partitions to extract (default: extract all)",
    )
    parser.add_argument(
        "--workers",
        default=cpu_count(),
        type=int,
        help="numer of workers (default: CPU count - %d)" % cpu_count(),
    )
    args = parser.parse_args()

    # Check for --out directory exists
    if not os.path.exists(args.out):
        os.makedirs(args.out)

    dumper = Dumper(
        args.payloadfile,
        args.out,
        diff=args.diff,
        old=args.old,
        images=args.partitions,
        workers=args.workers,
    )
    dumper.run()


if __name__ == "__main__":
    main()
