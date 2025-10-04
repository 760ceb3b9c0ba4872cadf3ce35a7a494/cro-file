from cro import CROFile


def main():
	# change to your CRO path
	with open("./oss.cro", "rb") as stream:
		cro_file = CROFile.from_stream(stream)
	print_contents(cro_file)

	with open("./out.cro", "wb") as out_stream:
		cro_file.to_stream(out_stream)


def print_contents(cro_file: CROFile):
	print(f"CRO file {cro_file.name!r}:")
	print(f"\tSegments:")
	for segment in cro_file.segments:
		print(f"\t\t{segment}")

	print(f"\tExported named symbols:")
	preview_count = 8
	for symbol in cro_file.exported_named_symbols[0:preview_count]:
		print(f"\t\t{symbol.name}")
	if len(cro_file.exported_named_symbols) > preview_count:
		print(f"\t\t... {len(cro_file.exported_named_symbols) - preview_count} more")

	print(f"\tImported named symbols:")
	preview_count = 8
	for symbol in cro_file.imported_named_symbols[0:preview_count]:
		print(f"\t\t{symbol.name}")
	if len(cro_file.imported_named_symbols) > preview_count:
		print(f"\t\t... {len(cro_file.imported_named_symbols) - preview_count} more")

	print(f"\tRelocations:")
	preview_count = 8
	for reloc in cro_file.relocations[0:preview_count]:
		print(f"\t\t{reloc.type.name} {reloc.base_index} @ {reloc.segment_type.name} {reloc.segment_offset}")
	if len(cro_file.relocations) > preview_count:
		print(f"\t\t... {len(cro_file.relocations) - preview_count} more")

	print("\t")


if __name__ == "__main__":
	main()
