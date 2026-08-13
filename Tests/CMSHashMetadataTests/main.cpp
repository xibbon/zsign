#include "signing.h"

#include <iostream>

static bool require(bool condition, const char* message)
{
	if (!condition) {
		std::cerr << message << std::endl;
	}
	return condition;
}

static bool requireHashAgilityValue(
	X509_ATTRIBUTE* attribute,
	int index,
	int algorithmNID,
	const string& digest)
{
	ASN1_TYPE* value = X509_ATTRIBUTE_get0_type(attribute, index);
	if (!require(value && value->type == V_ASN1_SEQUENCE,
		"Hash-agility value is not an ASN.1 sequence.")) {
		return false;
	}

	const unsigned char* data = value->value.sequence->data;
	STACK_OF(ASN1_TYPE)* sequence = d2i_ASN1_SEQUENCE_ANY(
		NULL,
		&data,
		value->value.sequence->length);
	if (!require(sequence && sk_ASN1_TYPE_num(sequence) == 2,
		"Hash-agility sequence has an invalid structure.")) {
		sk_ASN1_TYPE_pop_free(sequence, ASN1_TYPE_free);
		return false;
	}

	ASN1_TYPE* algorithm = sk_ASN1_TYPE_value(sequence, 0);
	ASN1_TYPE* hash = sk_ASN1_TYPE_value(sequence, 1);
	bool valid =
		require(algorithm->type == V_ASN1_OBJECT &&
			OBJ_obj2nid(algorithm->value.object) == algorithmNID,
			"Hash-agility sequence has the wrong algorithm.") &&
		require(hash->type == V_ASN1_OCTET_STRING,
			"Hash-agility sequence has an invalid digest type.") &&
		require(
			string(
				reinterpret_cast<const char*>(
					ASN1_STRING_get0_data(hash->value.octet_string)),
				ASN1_STRING_length(hash->value.octet_string)) == digest,
			"Hash-agility sequence has the wrong digest.");
	sk_ASN1_TYPE_pop_free(sequence, ASN1_TYPE_free);
	return valid;
}

int main()
{
	string plist;
	string sha1;
	string sha256;

	if (!require(
			ZSign::BuildCodeDirectoryHashes("sha256-code-directory", "", plist, sha1, sha256),
			"Could not build SHA-256-only hash metadata.")) {
		return 1;
	}

	jvalue singleHashes;
	if (!require(singleHashes.read_plist(plist), "Could not parse SHA-256-only hash plist.") ||
		!require(sha1.empty(), "SHA-256-only metadata contains a fabricated SHA-1 hash.") ||
		!require(sha256.size() == 32, "SHA-256-only metadata has an invalid full hash.") ||
		!require(singleHashes["cdhashes"].size() == 1, "SHA-256-only metadata must contain one cdhash.") ||
		!require(singleHashes["cdhashes"][0].as_data() == sha256.substr(0, 20),
			"SHA-256-only cdhash does not match its CodeDirectory hash.")) {
		return 1;
	}

	X509_ATTRIBUTE* singleAttribute =
		(X509_ATTRIBUTE*)ZSignAsset::GenerateHashAgilityAttribute(sha1, sha256);
	if (!require(singleAttribute != NULL, "Could not build the SHA-256-only hash-agility attribute.") ||
		!require(X509_ATTRIBUTE_count(singleAttribute) == 1,
			"SHA-256-only hash agility must contain one value.") ||
		!requireHashAgilityValue(singleAttribute, 0, NID_sha256, sha256)) {
		X509_ATTRIBUTE_free(singleAttribute);
		return 1;
	}
	X509_ATTRIBUTE_free(singleAttribute);

	if (!require(
			ZSign::BuildCodeDirectoryHashes(
				"sha1-code-directory",
				"sha256-code-directory",
				plist,
				sha1,
				sha256),
			"Could not build dual-CodeDirectory hash metadata.")) {
		return 1;
	}

	jvalue dualHashes;
	if (!require(dualHashes.read_plist(plist), "Could not parse dual-CodeDirectory hash plist.") ||
		!require(sha1.size() == 20, "Dual-CodeDirectory metadata has an invalid SHA-1 hash.") ||
		!require(sha256.size() == 32, "Dual-CodeDirectory metadata has an invalid SHA-256 hash.") ||
		!require(dualHashes["cdhashes"].size() == 2, "Dual-CodeDirectory metadata must contain two cdhashes.") ||
		!require(dualHashes["cdhashes"][0].as_data() == sha1,
			"The first dual-CodeDirectory cdhash is not SHA-1.") ||
		!require(dualHashes["cdhashes"][1].as_data() == sha256.substr(0, 20),
			"The second dual-CodeDirectory cdhash is not SHA-256.")) {
		return 1;
	}

	X509_ATTRIBUTE* dualAttribute =
		(X509_ATTRIBUTE*)ZSignAsset::GenerateHashAgilityAttribute(sha1, sha256);
	if (!require(dualAttribute != NULL, "Could not build the dual hash-agility attribute.") ||
		!require(X509_ATTRIBUTE_count(dualAttribute) == 2,
			"Dual hash agility must contain two values.") ||
		!requireHashAgilityValue(dualAttribute, 0, NID_sha1, sha1) ||
		!requireHashAgilityValue(dualAttribute, 1, NID_sha256, sha256)) {
		X509_ATTRIBUTE_free(dualAttribute);
		return 1;
	}
	X509_ATTRIBUTE_free(dualAttribute);

	std::cout << "CMS hash metadata tests passed." << std::endl;
	return 0;
}
