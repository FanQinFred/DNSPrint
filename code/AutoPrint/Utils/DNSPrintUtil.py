#  Copyright (c) 2023 fanqin. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
#  Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
#  Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
#  Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
#  Vestibulum commodo. Ut rhoncus gravida arcu.

import csv

from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from simcse import SimCSE  # https://github.com/princeton-nlp/SimCSE
import torch

model = SimCSE("princeton-nlp/unsup-simcse-bert-base-uncased")


def encode_domain(domain_name):
    embeddings = model.encode(str(domain_name), return_numpy=True, max_length=128)
    return embeddings


def process_pcap_file_to_csv(pcap_file, csv_file, label, packet_max_count=-1, device='cpu'):
    line_length = 0
    save_file = open(csv_file, 'w+', encoding='utf-8', newline='')
    writer = csv.writer(save_file)

    ##############################################################
    ######################### Header #############################
    ##############################################################

    ip_header = [
        "ip_version_0",
        "ip_version_1",
        "ip_version_2",
        "ip_version_3",

        "ip_ihl_0",
        "ip_ihl_1",
        "ip_ihl_2",
        "ip_ihl_3",

        "ip_tos_0",
        "ip_tos_1",
        "ip_tos_2",
        "ip_tos_3",
        "ip_tos_4",
        "ip_tos_5",
        "ip_tos_6",
        "ip_tos_7",

        "ip_len_0",
        "ip_len_1",
        "ip_len_2",
        "ip_len_3",
        "ip_len_4",
        "ip_len_5",
        "ip_len_6",
        "ip_len_7",
        "ip_len_8",
        "ip_len_9",
        "ip_len_10",
        "ip_len_11",
        "ip_len_12",
        "ip_len_13",
        "ip_len_14",
        "ip_len_15",

        "ip_id_0",
        "ip_id_1",
        "ip_id_2",
        "ip_id_3",
        "ip_id_4",
        "ip_id_5",
        "ip_id_6",
        "ip_id_7",
        "ip_id_8",
        "ip_id_9",
        "ip_id_10",
        "ip_id_11",
        "ip_id_12",
        "ip_id_13",
        "ip_id_14",
        "ip_id_15",

        "ip_flags_0",
        "ip_flags_1",
        "ip_flags_2",

        "ip_frag_0",
        "ip_frag_1",
        "ip_frag_2",
        "ip_frag_3",
        "ip_frag_4",
        "ip_frag_5",
        "ip_frag_6",
        "ip_frag_7",
        "ip_frag_8",
        "ip_frag_9",
        "ip_frag_10",
        "ip_frag_11",
        "ip_frag_12",

        "ip_ttl_0",
        "ip_ttl_1",
        "ip_ttl_2",
        "ip_ttl_3",
        "ip_ttl_4",
        "ip_ttl_5",
        "ip_ttl_6",
        "ip_ttl_7",

        "ip_proto_0",
        "ip_proto_1",
        "ip_proto_2",
        "ip_proto_3",
        "ip_proto_4",
        "ip_proto_5",
        "ip_proto_6",
        "ip_proto_7",

        "ip_chksum_0",
        "ip_chksum_1",
        "ip_chksum_2",
        "ip_chksum_3",
        "ip_chksum_4",
        "ip_chksum_5",
        "ip_chksum_6",
        "ip_chksum_7",
        "ip_chksum_8",
        "ip_chksum_9",
        "ip_chksum_10",
        "ip_chksum_11",
        "ip_chksum_12",
        "ip_chksum_13",
        "ip_chksum_14",
        "ip_chksum_15",

        "ip_src_0",
        "ip_src_1",
        "ip_src_2",
        "ip_src_3",
        "ip_src_4",
        "ip_src_5",
        "ip_src_6",
        "ip_src_7",
        "ip_src_8",
        "ip_src_9",
        "ip_src_10",
        "ip_src_11",
        "ip_src_12",
        "ip_src_13",
        "ip_src_14",
        "ip_src_15",
        "ip_src_16",
        "ip_src_17",
        "ip_src_18",
        "ip_src_19",
        "ip_src_20",
        "ip_src_21",
        "ip_src_22",
        "ip_src_23",
        "ip_src_24",
        "ip_src_25",
        "ip_src_26",
        "ip_src_27",
        "ip_src_28",
        "ip_src_29",
        "ip_src_30",
        "ip_src_31",

        "ip_dst_0",
        "ip_dst_1",
        "ip_dst_2",
        "ip_dst_3",
        "ip_dst_4",
        "ip_dst_5",
        "ip_dst_6",
        "ip_dst_7",
        "ip_dst_8",
        "ip_dst_9",
        "ip_dst_10",
        "ip_dst_11",
        "ip_dst_12",
        "ip_dst_13",
        "ip_dst_14",
        "ip_dst_15",
        "ip_dst_16",
        "ip_dst_17",
        "ip_dst_18",
        "ip_dst_19",
        "ip_dst_20",
        "ip_dst_21",
        "ip_dst_22",
        "ip_dst_23",
        "ip_dst_24",
        "ip_dst_25",
        "ip_dst_26",
        "ip_dst_27",
        "ip_dst_28",
        "ip_dst_29",
        "ip_dst_30",
        "ip_dst_31"
    ]

    udp_header = [
        "udp_sport_0",
        "udp_sport_1",
        "udp_sport_2",
        "udp_sport_3",
        "udp_sport_4",
        "udp_sport_5",
        "udp_sport_6",
        "udp_sport_7",
        "udp_sport_8",
        "udp_sport_9",
        "udp_sport_10",
        "udp_sport_11",
        "udp_sport_12",
        "udp_sport_13",
        "udp_sport_14",
        "udp_sport_15",

        "udp_dport_0",
        "udp_dport_1",
        "udp_dport_2",
        "udp_dport_3",
        "udp_dport_4",
        "udp_dport_5",
        "udp_dport_6",
        "udp_dport_7",
        "udp_dport_8",
        "udp_dport_9",
        "udp_dport_10",
        "udp_dport_11",
        "udp_dport_12",
        "udp_dport_13",
        "udp_dport_14",
        "udp_dport_15",

        "udp_len_0",
        "udp_len_1",
        "udp_len_2",
        "udp_len_3",
        "udp_len_4",
        "udp_len_5",
        "udp_len_6",
        "udp_len_7",
        "udp_len_8",
        "udp_len_9",
        "udp_len_10",
        "udp_len_11",
        "udp_len_12",
        "udp_len_13",
        "udp_len_14",
        "udp_len_15",

        "udp_chksum_0",
        "udp_chksum_1",
        "udp_chksum_2",
        "udp_chksum_3",
        "udp_chksum_4",
        "udp_chksum_5",
        "udp_chksum_6",
        "udp_chksum_7",
        "udp_chksum_8",
        "udp_chksum_9",
        "udp_chksum_10",
        "udp_chksum_11",
        "udp_chksum_12",
        "udp_chksum_13",
        "udp_chksum_14",
        "udp_chksum_15"
    ]

    dns_header = [
        "dns_identifacation_0",
        "dns_identifacation_1",
        "dns_identifacation_2",
        "dns_identifacation_3",
        "dns_identifacation_4",
        "dns_identifacation_5",
        "dns_identifacation_6",
        "dns_identifacation_7",
        "dns_identifacation_8",
        "dns_identifacation_9",
        "dns_identifacation_10",
        "dns_identifacation_11",
        "dns_identifacation_12",
        "dns_identifacation_13",
        "dns_identifacation_14",
        "dns_identifacation_15",

        "dns_qr",

        "dns_opcode_0",
        "dns_opcode_1",
        "dns_opcode_2",
        "dns_opcode_3",

        "dns_aa",

        "dns_tc",

        "dns_rd",

        "dns_ra",

        "dns_z",

        "dns_ad",

        "dns_cd",

        "dns_rcode_0",
        "dns_rcode_1",
        "dns_rcode_2",
        "dns_rcode_3",

        "dns_qdcount_0",
        "dns_qdcount_1",
        "dns_qdcount_2",
        "dns_qdcount_3",
        "dns_qdcount_4",
        "dns_qdcount_5",
        "dns_qdcount_6",
        "dns_qdcount_7",
        "dns_qdcount_8",
        "dns_qdcount_9",
        "dns_qdcount_10",
        "dns_qdcount_11",
        "dns_qdcount_12",
        "dns_qdcount_13",
        "dns_qdcount_14",
        "dns_qdcount_15",

        "dns_ancount_0",
        "dns_ancount_1",
        "dns_ancount_2",
        "dns_ancount_3",
        "dns_ancount_4",
        "dns_ancount_5",
        "dns_ancount_6",
        "dns_ancount_7",
        "dns_ancount_8",
        "dns_ancount_9",
        "dns_ancount_10",
        "dns_ancount_11",
        "dns_ancount_12",
        "dns_ancount_13",
        "dns_ancount_14",
        "dns_ancount_15",

        "dns_nscount_0",
        "dns_nscount_1",
        "dns_nscount_2",
        "dns_nscount_3",
        "dns_nscount_4",
        "dns_nscount_5",
        "dns_nscount_6",
        "dns_nscount_7",
        "dns_nscount_8",
        "dns_nscount_9",
        "dns_nscount_10",
        "dns_nscount_11",
        "dns_nscount_12",
        "dns_nscount_13",
        "dns_nscount_14",
        "dns_nscount_15",

        "dns_arcount_0",
        "dns_arcount_1",
        "dns_arcount_2",
        "dns_arcount_3",
        "dns_arcount_4",
        "dns_arcount_5",
        "dns_arcount_6",
        "dns_arcount_7",
        "dns_arcount_8",
        "dns_arcount_9",
        "dns_arcount_10",
        "dns_arcount_11",
        "dns_arcount_12",
        "dns_arcount_13",
        "dns_arcount_14",
        "dns_arcount_15",

        "dns_qd_0", "dns_qd_1", "dns_qd_2", "dns_qd_3", "dns_qd_4", "dns_qd_5", "dns_qd_6", "dns_qd_7", "dns_qd_8",
        "dns_qd_9", "dns_qd_10", "dns_qd_11", "dns_qd_12", "dns_qd_13", "dns_qd_14", "dns_qd_15", "dns_qd_16",
        "dns_qd_17", "dns_qd_18", "dns_qd_19", "dns_qd_20", "dns_qd_21", "dns_qd_22", "dns_qd_23", "dns_qd_24",
        "dns_qd_25", "dns_qd_26", "dns_qd_27", "dns_qd_28", "dns_qd_29", "dns_qd_30", "dns_qd_31", "dns_qd_32",
        "dns_qd_33", "dns_qd_34", "dns_qd_35", "dns_qd_36", "dns_qd_37", "dns_qd_38", "dns_qd_39", "dns_qd_40",
        "dns_qd_41", "dns_qd_42", "dns_qd_43", "dns_qd_44", "dns_qd_45", "dns_qd_46", "dns_qd_47", "dns_qd_48",
        "dns_qd_49", "dns_qd_50", "dns_qd_51", "dns_qd_52", "dns_qd_53", "dns_qd_54", "dns_qd_55", "dns_qd_56",
        "dns_qd_57", "dns_qd_58", "dns_qd_59", "dns_qd_60", "dns_qd_61", "dns_qd_62", "dns_qd_63", "dns_qd_64",
        "dns_qd_65", "dns_qd_66", "dns_qd_67", "dns_qd_68", "dns_qd_69", "dns_qd_70", "dns_qd_71", "dns_qd_72",
        "dns_qd_73", "dns_qd_74", "dns_qd_75", "dns_qd_76", "dns_qd_77", "dns_qd_78", "dns_qd_79", "dns_qd_80",
        "dns_qd_81", "dns_qd_82", "dns_qd_83", "dns_qd_84", "dns_qd_85", "dns_qd_86", "dns_qd_87", "dns_qd_88",
        "dns_qd_89", "dns_qd_90", "dns_qd_91", "dns_qd_92", "dns_qd_93", "dns_qd_94", "dns_qd_95", "dns_qd_96",
        "dns_qd_97", "dns_qd_98", "dns_qd_99", "dns_qd_100", "dns_qd_101", "dns_qd_102", "dns_qd_103", "dns_qd_104",
        "dns_qd_105", "dns_qd_106", "dns_qd_107", "dns_qd_108", "dns_qd_109", "dns_qd_110", "dns_qd_111", "dns_qd_112",
        "dns_qd_113", "dns_qd_114", "dns_qd_115", "dns_qd_116", "dns_qd_117", "dns_qd_118", "dns_qd_119", "dns_qd_120",
        "dns_qd_121", "dns_qd_122", "dns_qd_123", "dns_qd_124", "dns_qd_125", "dns_qd_126", "dns_qd_127", "dns_qd_128",
        "dns_qd_129", "dns_qd_130", "dns_qd_131", "dns_qd_132", "dns_qd_133", "dns_qd_134", "dns_qd_135", "dns_qd_136",
        "dns_qd_137", "dns_qd_138", "dns_qd_139", "dns_qd_140", "dns_qd_141", "dns_qd_142", "dns_qd_143", "dns_qd_144",
        "dns_qd_145", "dns_qd_146", "dns_qd_147", "dns_qd_148", "dns_qd_149", "dns_qd_150", "dns_qd_151", "dns_qd_152",
        "dns_qd_153", "dns_qd_154", "dns_qd_155", "dns_qd_156", "dns_qd_157", "dns_qd_158", "dns_qd_159", "dns_qd_160",
        "dns_qd_161", "dns_qd_162", "dns_qd_163", "dns_qd_164", "dns_qd_165", "dns_qd_166", "dns_qd_167", "dns_qd_168",
        "dns_qd_169", "dns_qd_170", "dns_qd_171", "dns_qd_172", "dns_qd_173", "dns_qd_174", "dns_qd_175", "dns_qd_176",
        "dns_qd_177", "dns_qd_178", "dns_qd_179", "dns_qd_180", "dns_qd_181", "dns_qd_182", "dns_qd_183", "dns_qd_184",
        "dns_qd_185", "dns_qd_186", "dns_qd_187", "dns_qd_188", "dns_qd_189", "dns_qd_190", "dns_qd_191", "dns_qd_192",
        "dns_qd_193", "dns_qd_194", "dns_qd_195", "dns_qd_196", "dns_qd_197", "dns_qd_198", "dns_qd_199", "dns_qd_200",
        "dns_qd_201", "dns_qd_202", "dns_qd_203", "dns_qd_204", "dns_qd_205", "dns_qd_206", "dns_qd_207", "dns_qd_208",
        "dns_qd_209", "dns_qd_210", "dns_qd_211", "dns_qd_212", "dns_qd_213", "dns_qd_214", "dns_qd_215", "dns_qd_216",
        "dns_qd_217", "dns_qd_218", "dns_qd_219", "dns_qd_220", "dns_qd_221", "dns_qd_222", "dns_qd_223", "dns_qd_224",
        "dns_qd_225", "dns_qd_226", "dns_qd_227", "dns_qd_228", "dns_qd_229", "dns_qd_230", "dns_qd_231", "dns_qd_232",
        "dns_qd_233", "dns_qd_234", "dns_qd_235", "dns_qd_236", "dns_qd_237", "dns_qd_238", "dns_qd_239", "dns_qd_240",
        "dns_qd_241", "dns_qd_242", "dns_qd_243", "dns_qd_244", "dns_qd_245", "dns_qd_246", "dns_qd_247", "dns_qd_248",
        "dns_qd_249", "dns_qd_250", "dns_qd_251", "dns_qd_252", "dns_qd_253", "dns_qd_254", "dns_qd_255", "dns_qd_256",
        "dns_qd_257", "dns_qd_258", "dns_qd_259", "dns_qd_260", "dns_qd_261", "dns_qd_262", "dns_qd_263", "dns_qd_264",
        "dns_qd_265", "dns_qd_266", "dns_qd_267", "dns_qd_268", "dns_qd_269", "dns_qd_270", "dns_qd_271", "dns_qd_272",
        "dns_qd_273", "dns_qd_274", "dns_qd_275", "dns_qd_276", "dns_qd_277", "dns_qd_278", "dns_qd_279", "dns_qd_280",
        "dns_qd_281", "dns_qd_282", "dns_qd_283", "dns_qd_284", "dns_qd_285", "dns_qd_286", "dns_qd_287", "dns_qd_288",
        "dns_qd_289", "dns_qd_290", "dns_qd_291", "dns_qd_292", "dns_qd_293", "dns_qd_294", "dns_qd_295", "dns_qd_296",
        "dns_qd_297", "dns_qd_298", "dns_qd_299", "dns_qd_300", "dns_qd_301", "dns_qd_302", "dns_qd_303", "dns_qd_304",
        "dns_qd_305", "dns_qd_306", "dns_qd_307", "dns_qd_308", "dns_qd_309", "dns_qd_310", "dns_qd_311", "dns_qd_312",
        "dns_qd_313", "dns_qd_314", "dns_qd_315", "dns_qd_316", "dns_qd_317", "dns_qd_318", "dns_qd_319", "dns_qd_320",
        "dns_qd_321", "dns_qd_322", "dns_qd_323", "dns_qd_324", "dns_qd_325", "dns_qd_326", "dns_qd_327", "dns_qd_328",
        "dns_qd_329", "dns_qd_330", "dns_qd_331", "dns_qd_332", "dns_qd_333", "dns_qd_334", "dns_qd_335", "dns_qd_336",
        "dns_qd_337", "dns_qd_338", "dns_qd_339", "dns_qd_340", "dns_qd_341", "dns_qd_342", "dns_qd_343", "dns_qd_344",
        "dns_qd_345", "dns_qd_346", "dns_qd_347", "dns_qd_348", "dns_qd_349", "dns_qd_350", "dns_qd_351", "dns_qd_352",
        "dns_qd_353", "dns_qd_354", "dns_qd_355", "dns_qd_356", "dns_qd_357", "dns_qd_358", "dns_qd_359", "dns_qd_360",
        "dns_qd_361", "dns_qd_362", "dns_qd_363", "dns_qd_364", "dns_qd_365", "dns_qd_366", "dns_qd_367", "dns_qd_368",
        "dns_qd_369", "dns_qd_370", "dns_qd_371", "dns_qd_372", "dns_qd_373", "dns_qd_374", "dns_qd_375", "dns_qd_376",
        "dns_qd_377", "dns_qd_378", "dns_qd_379", "dns_qd_380", "dns_qd_381", "dns_qd_382", "dns_qd_383", "dns_qd_384",
        "dns_qd_385", "dns_qd_386", "dns_qd_387", "dns_qd_388", "dns_qd_389", "dns_qd_390", "dns_qd_391", "dns_qd_392",
        "dns_qd_393", "dns_qd_394", "dns_qd_395", "dns_qd_396", "dns_qd_397", "dns_qd_398", "dns_qd_399", "dns_qd_400",
        "dns_qd_401", "dns_qd_402", "dns_qd_403", "dns_qd_404", "dns_qd_405", "dns_qd_406", "dns_qd_407", "dns_qd_408",
        "dns_qd_409", "dns_qd_410", "dns_qd_411", "dns_qd_412", "dns_qd_413", "dns_qd_414", "dns_qd_415", "dns_qd_416",
        "dns_qd_417", "dns_qd_418", "dns_qd_419", "dns_qd_420", "dns_qd_421", "dns_qd_422", "dns_qd_423", "dns_qd_424",
        "dns_qd_425", "dns_qd_426", "dns_qd_427", "dns_qd_428", "dns_qd_429", "dns_qd_430", "dns_qd_431", "dns_qd_432",
        "dns_qd_433", "dns_qd_434", "dns_qd_435", "dns_qd_436", "dns_qd_437", "dns_qd_438", "dns_qd_439", "dns_qd_440",
        "dns_qd_441", "dns_qd_442", "dns_qd_443", "dns_qd_444", "dns_qd_445", "dns_qd_446", "dns_qd_447", "dns_qd_448",
        "dns_qd_449", "dns_qd_450", "dns_qd_451", "dns_qd_452", "dns_qd_453", "dns_qd_454", "dns_qd_455", "dns_qd_456",
        "dns_qd_457", "dns_qd_458", "dns_qd_459", "dns_qd_460", "dns_qd_461", "dns_qd_462", "dns_qd_463", "dns_qd_464",
        "dns_qd_465", "dns_qd_466", "dns_qd_467", "dns_qd_468", "dns_qd_469", "dns_qd_470", "dns_qd_471", "dns_qd_472",
        "dns_qd_473", "dns_qd_474", "dns_qd_475", "dns_qd_476", "dns_qd_477", "dns_qd_478", "dns_qd_479", "dns_qd_480",
        "dns_qd_481", "dns_qd_482", "dns_qd_483", "dns_qd_484", "dns_qd_485", "dns_qd_486", "dns_qd_487", "dns_qd_488",
        "dns_qd_489", "dns_qd_490", "dns_qd_491", "dns_qd_492", "dns_qd_493", "dns_qd_494", "dns_qd_495", "dns_qd_496",
        "dns_qd_497", "dns_qd_498", "dns_qd_499", "dns_qd_500", "dns_qd_501", "dns_qd_502", "dns_qd_503", "dns_qd_504",
        "dns_qd_505", "dns_qd_506", "dns_qd_507", "dns_qd_508", "dns_qd_509", "dns_qd_510", "dns_qd_511", "dns_qd_512",
        "dns_qd_513", "dns_qd_514", "dns_qd_515", "dns_qd_516", "dns_qd_517", "dns_qd_518", "dns_qd_519", "dns_qd_520",
        "dns_qd_521", "dns_qd_522", "dns_qd_523", "dns_qd_524", "dns_qd_525", "dns_qd_526", "dns_qd_527", "dns_qd_528",
        "dns_qd_529", "dns_qd_530", "dns_qd_531", "dns_qd_532", "dns_qd_533", "dns_qd_534", "dns_qd_535", "dns_qd_536",
        "dns_qd_537", "dns_qd_538", "dns_qd_539", "dns_qd_540", "dns_qd_541", "dns_qd_542", "dns_qd_543", "dns_qd_544",
        "dns_qd_545", "dns_qd_546", "dns_qd_547", "dns_qd_548", "dns_qd_549", "dns_qd_550", "dns_qd_551", "dns_qd_552",
        "dns_qd_553", "dns_qd_554", "dns_qd_555", "dns_qd_556", "dns_qd_557", "dns_qd_558", "dns_qd_559", "dns_qd_560",
        "dns_qd_561", "dns_qd_562", "dns_qd_563", "dns_qd_564", "dns_qd_565", "dns_qd_566", "dns_qd_567", "dns_qd_568",
        "dns_qd_569", "dns_qd_570", "dns_qd_571", "dns_qd_572", "dns_qd_573", "dns_qd_574", "dns_qd_575", "dns_qd_576",
        "dns_qd_577", "dns_qd_578", "dns_qd_579", "dns_qd_580", "dns_qd_581", "dns_qd_582", "dns_qd_583", "dns_qd_584",
        "dns_qd_585", "dns_qd_586", "dns_qd_587", "dns_qd_588", "dns_qd_589", "dns_qd_590", "dns_qd_591", "dns_qd_592",
        "dns_qd_593", "dns_qd_594", "dns_qd_595", "dns_qd_596", "dns_qd_597", "dns_qd_598", "dns_qd_599", "dns_qd_600",
        "dns_qd_601", "dns_qd_602", "dns_qd_603", "dns_qd_604", "dns_qd_605", "dns_qd_606", "dns_qd_607", "dns_qd_608",
        "dns_qd_609", "dns_qd_610", "dns_qd_611", "dns_qd_612", "dns_qd_613", "dns_qd_614", "dns_qd_615", "dns_qd_616",
        "dns_qd_617", "dns_qd_618", "dns_qd_619", "dns_qd_620", "dns_qd_621", "dns_qd_622", "dns_qd_623", "dns_qd_624",
        "dns_qd_625", "dns_qd_626", "dns_qd_627", "dns_qd_628", "dns_qd_629", "dns_qd_630", "dns_qd_631", "dns_qd_632",
        "dns_qd_633", "dns_qd_634", "dns_qd_635", "dns_qd_636", "dns_qd_637", "dns_qd_638", "dns_qd_639", "dns_qd_640",
        "dns_qd_641", "dns_qd_642", "dns_qd_643", "dns_qd_644", "dns_qd_645", "dns_qd_646", "dns_qd_647", "dns_qd_648",
        "dns_qd_649", "dns_qd_650", "dns_qd_651", "dns_qd_652", "dns_qd_653", "dns_qd_654", "dns_qd_655", "dns_qd_656",
        "dns_qd_657", "dns_qd_658", "dns_qd_659", "dns_qd_660", "dns_qd_661", "dns_qd_662", "dns_qd_663", "dns_qd_664",
        "dns_qd_665", "dns_qd_666", "dns_qd_667", "dns_qd_668", "dns_qd_669", "dns_qd_670", "dns_qd_671", "dns_qd_672",
        "dns_qd_673", "dns_qd_674", "dns_qd_675", "dns_qd_676", "dns_qd_677", "dns_qd_678", "dns_qd_679", "dns_qd_680",
        "dns_qd_681", "dns_qd_682", "dns_qd_683", "dns_qd_684", "dns_qd_685", "dns_qd_686", "dns_qd_687", "dns_qd_688",
        "dns_qd_689", "dns_qd_690", "dns_qd_691", "dns_qd_692", "dns_qd_693", "dns_qd_694", "dns_qd_695", "dns_qd_696",
        "dns_qd_697", "dns_qd_698", "dns_qd_699", "dns_qd_700", "dns_qd_701", "dns_qd_702", "dns_qd_703", "dns_qd_704",
        "dns_qd_705", "dns_qd_706", "dns_qd_707", "dns_qd_708", "dns_qd_709", "dns_qd_710", "dns_qd_711", "dns_qd_712",
        "dns_qd_713", "dns_qd_714", "dns_qd_715", "dns_qd_716", "dns_qd_717", "dns_qd_718", "dns_qd_719", "dns_qd_720",
        "dns_qd_721", "dns_qd_722", "dns_qd_723", "dns_qd_724", "dns_qd_725", "dns_qd_726", "dns_qd_727", "dns_qd_728",
        "dns_qd_729", "dns_qd_730", "dns_qd_731", "dns_qd_732", "dns_qd_733", "dns_qd_734", "dns_qd_735", "dns_qd_736",
        "dns_qd_737", "dns_qd_738", "dns_qd_739", "dns_qd_740", "dns_qd_741", "dns_qd_742", "dns_qd_743", "dns_qd_744",
        "dns_qd_745", "dns_qd_746", "dns_qd_747", "dns_qd_748", "dns_qd_749", "dns_qd_750", "dns_qd_751", "dns_qd_752",
        "dns_qd_753", "dns_qd_754", "dns_qd_755", "dns_qd_756", "dns_qd_757", "dns_qd_758", "dns_qd_759", "dns_qd_760",
        "dns_qd_761", "dns_qd_762", "dns_qd_763", "dns_qd_764", "dns_qd_765", "dns_qd_766", "dns_qd_767", "dns_qd_768",
        "dns_qd_769", "dns_qd_770", "dns_qd_771", "dns_qd_772", "dns_qd_773", "dns_qd_774", "dns_qd_775", "dns_qd_776",
        "dns_qd_777", "dns_qd_778", "dns_qd_779", "dns_qd_780", "dns_qd_781", "dns_qd_782", "dns_qd_783", "dns_qd_784",
        "dns_qd_785", "dns_qd_786", "dns_qd_787", "dns_qd_788", "dns_qd_789", "dns_qd_790", "dns_qd_791", "dns_qd_792",
        "dns_qd_793", "dns_qd_794", "dns_qd_795", "dns_qd_796", "dns_qd_797", "dns_qd_798", "dns_qd_799",

        "dns_an_0", "dns_an_1", "dns_an_2", "dns_an_3", "dns_an_4", "dns_an_5", "dns_an_6", "dns_an_7", "dns_an_8",
        "dns_an_9", "dns_an_10", "dns_an_11", "dns_an_12", "dns_an_13", "dns_an_14", "dns_an_15", "dns_an_16",
        "dns_an_17", "dns_an_18", "dns_an_19", "dns_an_20", "dns_an_21", "dns_an_22", "dns_an_23", "dns_an_24",
        "dns_an_25", "dns_an_26", "dns_an_27", "dns_an_28", "dns_an_29", "dns_an_30", "dns_an_31", "dns_an_32",
        "dns_an_33", "dns_an_34", "dns_an_35", "dns_an_36", "dns_an_37", "dns_an_38", "dns_an_39", "dns_an_40",
        "dns_an_41", "dns_an_42", "dns_an_43", "dns_an_44", "dns_an_45", "dns_an_46", "dns_an_47", "dns_an_48",
        "dns_an_49", "dns_an_50", "dns_an_51", "dns_an_52", "dns_an_53", "dns_an_54", "dns_an_55", "dns_an_56",
        "dns_an_57", "dns_an_58", "dns_an_59", "dns_an_60", "dns_an_61", "dns_an_62", "dns_an_63", "dns_an_64",
        "dns_an_65", "dns_an_66", "dns_an_67", "dns_an_68", "dns_an_69", "dns_an_70", "dns_an_71", "dns_an_72",
        "dns_an_73", "dns_an_74", "dns_an_75", "dns_an_76", "dns_an_77", "dns_an_78", "dns_an_79", "dns_an_80",
        "dns_an_81", "dns_an_82", "dns_an_83", "dns_an_84", "dns_an_85", "dns_an_86", "dns_an_87", "dns_an_88",
        "dns_an_89", "dns_an_90", "dns_an_91", "dns_an_92", "dns_an_93", "dns_an_94", "dns_an_95", "dns_an_96",
        "dns_an_97", "dns_an_98", "dns_an_99", "dns_an_100", "dns_an_101", "dns_an_102", "dns_an_103", "dns_an_104",
        "dns_an_105", "dns_an_106", "dns_an_107", "dns_an_108", "dns_an_109", "dns_an_110", "dns_an_111", "dns_an_112",
        "dns_an_113", "dns_an_114", "dns_an_115", "dns_an_116", "dns_an_117", "dns_an_118", "dns_an_119", "dns_an_120",
        "dns_an_121", "dns_an_122", "dns_an_123", "dns_an_124", "dns_an_125", "dns_an_126", "dns_an_127", "dns_an_128",
        "dns_an_129", "dns_an_130", "dns_an_131", "dns_an_132", "dns_an_133", "dns_an_134", "dns_an_135", "dns_an_136",
        "dns_an_137", "dns_an_138", "dns_an_139", "dns_an_140", "dns_an_141", "dns_an_142", "dns_an_143", "dns_an_144",
        "dns_an_145", "dns_an_146", "dns_an_147", "dns_an_148", "dns_an_149", "dns_an_150", "dns_an_151", "dns_an_152",
        "dns_an_153", "dns_an_154", "dns_an_155", "dns_an_156", "dns_an_157", "dns_an_158", "dns_an_159", "dns_an_160",
        "dns_an_161", "dns_an_162", "dns_an_163", "dns_an_164", "dns_an_165", "dns_an_166", "dns_an_167", "dns_an_168",
        "dns_an_169", "dns_an_170", "dns_an_171", "dns_an_172", "dns_an_173", "dns_an_174", "dns_an_175", "dns_an_176",
        "dns_an_177", "dns_an_178", "dns_an_179", "dns_an_180", "dns_an_181", "dns_an_182", "dns_an_183", "dns_an_184",
        "dns_an_185", "dns_an_186", "dns_an_187", "dns_an_188", "dns_an_189", "dns_an_190", "dns_an_191", "dns_an_192",
        "dns_an_193", "dns_an_194", "dns_an_195", "dns_an_196", "dns_an_197", "dns_an_198", "dns_an_199", "dns_an_200",
        "dns_an_201", "dns_an_202", "dns_an_203", "dns_an_204", "dns_an_205", "dns_an_206", "dns_an_207", "dns_an_208",
        "dns_an_209", "dns_an_210", "dns_an_211", "dns_an_212", "dns_an_213", "dns_an_214", "dns_an_215", "dns_an_216",
        "dns_an_217", "dns_an_218", "dns_an_219", "dns_an_220", "dns_an_221", "dns_an_222", "dns_an_223", "dns_an_224",
        "dns_an_225", "dns_an_226", "dns_an_227", "dns_an_228", "dns_an_229", "dns_an_230", "dns_an_231", "dns_an_232",
        "dns_an_233", "dns_an_234", "dns_an_235", "dns_an_236", "dns_an_237", "dns_an_238", "dns_an_239", "dns_an_240",
        "dns_an_241", "dns_an_242", "dns_an_243", "dns_an_244", "dns_an_245", "dns_an_246", "dns_an_247", "dns_an_248",
        "dns_an_249", "dns_an_250", "dns_an_251", "dns_an_252", "dns_an_253", "dns_an_254", "dns_an_255", "dns_an_256",
        "dns_an_257", "dns_an_258", "dns_an_259", "dns_an_260", "dns_an_261", "dns_an_262", "dns_an_263", "dns_an_264",
        "dns_an_265", "dns_an_266", "dns_an_267", "dns_an_268", "dns_an_269", "dns_an_270", "dns_an_271", "dns_an_272",
        "dns_an_273", "dns_an_274", "dns_an_275", "dns_an_276", "dns_an_277", "dns_an_278", "dns_an_279", "dns_an_280",
        "dns_an_281", "dns_an_282", "dns_an_283", "dns_an_284", "dns_an_285", "dns_an_286", "dns_an_287", "dns_an_288",
        "dns_an_289", "dns_an_290", "dns_an_291", "dns_an_292", "dns_an_293", "dns_an_294", "dns_an_295", "dns_an_296",
        "dns_an_297", "dns_an_298", "dns_an_299", "dns_an_300", "dns_an_301", "dns_an_302", "dns_an_303", "dns_an_304",
        "dns_an_305", "dns_an_306", "dns_an_307", "dns_an_308", "dns_an_309", "dns_an_310", "dns_an_311", "dns_an_312",
        "dns_an_313", "dns_an_314", "dns_an_315", "dns_an_316", "dns_an_317", "dns_an_318", "dns_an_319", "dns_an_320",
        "dns_an_321", "dns_an_322", "dns_an_323", "dns_an_324", "dns_an_325", "dns_an_326", "dns_an_327", "dns_an_328",
        "dns_an_329", "dns_an_330", "dns_an_331", "dns_an_332", "dns_an_333", "dns_an_334", "dns_an_335", "dns_an_336",
        "dns_an_337", "dns_an_338", "dns_an_339", "dns_an_340", "dns_an_341", "dns_an_342", "dns_an_343", "dns_an_344",
        "dns_an_345", "dns_an_346", "dns_an_347", "dns_an_348", "dns_an_349", "dns_an_350", "dns_an_351", "dns_an_352",
        "dns_an_353", "dns_an_354", "dns_an_355", "dns_an_356", "dns_an_357", "dns_an_358", "dns_an_359", "dns_an_360",
        "dns_an_361", "dns_an_362", "dns_an_363", "dns_an_364", "dns_an_365", "dns_an_366", "dns_an_367", "dns_an_368",
        "dns_an_369", "dns_an_370", "dns_an_371", "dns_an_372", "dns_an_373", "dns_an_374", "dns_an_375", "dns_an_376",
        "dns_an_377", "dns_an_378", "dns_an_379", "dns_an_380", "dns_an_381", "dns_an_382", "dns_an_383", "dns_an_384",
        "dns_an_385", "dns_an_386", "dns_an_387", "dns_an_388", "dns_an_389", "dns_an_390", "dns_an_391", "dns_an_392",
        "dns_an_393", "dns_an_394", "dns_an_395", "dns_an_396", "dns_an_397", "dns_an_398", "dns_an_399", "dns_an_400",
        "dns_an_401", "dns_an_402", "dns_an_403", "dns_an_404", "dns_an_405", "dns_an_406", "dns_an_407", "dns_an_408",
        "dns_an_409", "dns_an_410", "dns_an_411", "dns_an_412", "dns_an_413", "dns_an_414", "dns_an_415", "dns_an_416",
        "dns_an_417", "dns_an_418", "dns_an_419", "dns_an_420", "dns_an_421", "dns_an_422", "dns_an_423", "dns_an_424",
        "dns_an_425", "dns_an_426", "dns_an_427", "dns_an_428", "dns_an_429", "dns_an_430", "dns_an_431", "dns_an_432",
        "dns_an_433", "dns_an_434", "dns_an_435", "dns_an_436", "dns_an_437", "dns_an_438", "dns_an_439", "dns_an_440",
        "dns_an_441", "dns_an_442", "dns_an_443", "dns_an_444", "dns_an_445", "dns_an_446", "dns_an_447", "dns_an_448",
        "dns_an_449", "dns_an_450", "dns_an_451", "dns_an_452", "dns_an_453", "dns_an_454", "dns_an_455", "dns_an_456",
        "dns_an_457", "dns_an_458", "dns_an_459", "dns_an_460", "dns_an_461", "dns_an_462", "dns_an_463", "dns_an_464",
        "dns_an_465", "dns_an_466", "dns_an_467", "dns_an_468", "dns_an_469", "dns_an_470", "dns_an_471", "dns_an_472",
        "dns_an_473", "dns_an_474", "dns_an_475", "dns_an_476", "dns_an_477", "dns_an_478", "dns_an_479", "dns_an_480",
        "dns_an_481", "dns_an_482", "dns_an_483", "dns_an_484", "dns_an_485", "dns_an_486", "dns_an_487", "dns_an_488",
        "dns_an_489", "dns_an_490", "dns_an_491", "dns_an_492", "dns_an_493", "dns_an_494", "dns_an_495", "dns_an_496",
        "dns_an_497", "dns_an_498", "dns_an_499", "dns_an_500", "dns_an_501", "dns_an_502", "dns_an_503", "dns_an_504",
        "dns_an_505", "dns_an_506", "dns_an_507", "dns_an_508", "dns_an_509", "dns_an_510", "dns_an_511", "dns_an_512",
        "dns_an_513", "dns_an_514", "dns_an_515", "dns_an_516", "dns_an_517", "dns_an_518", "dns_an_519", "dns_an_520",
        "dns_an_521", "dns_an_522", "dns_an_523", "dns_an_524", "dns_an_525", "dns_an_526", "dns_an_527", "dns_an_528",
        "dns_an_529", "dns_an_530", "dns_an_531", "dns_an_532", "dns_an_533", "dns_an_534", "dns_an_535", "dns_an_536",
        "dns_an_537", "dns_an_538", "dns_an_539", "dns_an_540", "dns_an_541", "dns_an_542", "dns_an_543", "dns_an_544",
        "dns_an_545", "dns_an_546", "dns_an_547", "dns_an_548", "dns_an_549", "dns_an_550", "dns_an_551", "dns_an_552",
        "dns_an_553", "dns_an_554", "dns_an_555", "dns_an_556", "dns_an_557", "dns_an_558", "dns_an_559", "dns_an_560",
        "dns_an_561", "dns_an_562", "dns_an_563", "dns_an_564", "dns_an_565", "dns_an_566", "dns_an_567", "dns_an_568",
        "dns_an_569", "dns_an_570", "dns_an_571", "dns_an_572", "dns_an_573", "dns_an_574", "dns_an_575", "dns_an_576",
        "dns_an_577", "dns_an_578", "dns_an_579", "dns_an_580", "dns_an_581", "dns_an_582", "dns_an_583", "dns_an_584",
        "dns_an_585", "dns_an_586", "dns_an_587", "dns_an_588", "dns_an_589", "dns_an_590", "dns_an_591", "dns_an_592",
        "dns_an_593", "dns_an_594", "dns_an_595", "dns_an_596", "dns_an_597", "dns_an_598", "dns_an_599", "dns_an_600",
        "dns_an_601", "dns_an_602", "dns_an_603", "dns_an_604", "dns_an_605", "dns_an_606", "dns_an_607", "dns_an_608",
        "dns_an_609", "dns_an_610", "dns_an_611", "dns_an_612", "dns_an_613", "dns_an_614", "dns_an_615", "dns_an_616",
        "dns_an_617", "dns_an_618", "dns_an_619", "dns_an_620", "dns_an_621", "dns_an_622", "dns_an_623", "dns_an_624",
        "dns_an_625", "dns_an_626", "dns_an_627", "dns_an_628", "dns_an_629", "dns_an_630", "dns_an_631", "dns_an_632",
        "dns_an_633", "dns_an_634", "dns_an_635", "dns_an_636", "dns_an_637", "dns_an_638", "dns_an_639", "dns_an_640",
        "dns_an_641", "dns_an_642", "dns_an_643", "dns_an_644", "dns_an_645", "dns_an_646", "dns_an_647", "dns_an_648",
        "dns_an_649", "dns_an_650", "dns_an_651", "dns_an_652", "dns_an_653", "dns_an_654", "dns_an_655", "dns_an_656",
        "dns_an_657", "dns_an_658", "dns_an_659", "dns_an_660", "dns_an_661", "dns_an_662", "dns_an_663", "dns_an_664",
        "dns_an_665", "dns_an_666", "dns_an_667", "dns_an_668", "dns_an_669", "dns_an_670", "dns_an_671", "dns_an_672",
        "dns_an_673", "dns_an_674", "dns_an_675", "dns_an_676", "dns_an_677", "dns_an_678", "dns_an_679", "dns_an_680",
        "dns_an_681", "dns_an_682", "dns_an_683", "dns_an_684", "dns_an_685", "dns_an_686", "dns_an_687", "dns_an_688",
        "dns_an_689", "dns_an_690", "dns_an_691", "dns_an_692", "dns_an_693", "dns_an_694", "dns_an_695", "dns_an_696",
        "dns_an_697", "dns_an_698", "dns_an_699", "dns_an_700", "dns_an_701", "dns_an_702", "dns_an_703", "dns_an_704",
        "dns_an_705", "dns_an_706", "dns_an_707", "dns_an_708", "dns_an_709", "dns_an_710", "dns_an_711", "dns_an_712",
        "dns_an_713", "dns_an_714", "dns_an_715", "dns_an_716", "dns_an_717", "dns_an_718", "dns_an_719", "dns_an_720",
        "dns_an_721", "dns_an_722", "dns_an_723", "dns_an_724", "dns_an_725", "dns_an_726", "dns_an_727", "dns_an_728",
        "dns_an_729", "dns_an_730", "dns_an_731", "dns_an_732", "dns_an_733", "dns_an_734", "dns_an_735", "dns_an_736",
        "dns_an_737", "dns_an_738", "dns_an_739", "dns_an_740", "dns_an_741", "dns_an_742", "dns_an_743", "dns_an_744",
        "dns_an_745", "dns_an_746", "dns_an_747", "dns_an_748", "dns_an_749", "dns_an_750", "dns_an_751", "dns_an_752",
        "dns_an_753", "dns_an_754", "dns_an_755", "dns_an_756", "dns_an_757", "dns_an_758", "dns_an_759", "dns_an_760",
        "dns_an_761", "dns_an_762", "dns_an_763", "dns_an_764", "dns_an_765", "dns_an_766", "dns_an_767", "dns_an_768",
        "dns_an_769", "dns_an_770", "dns_an_771", "dns_an_772", "dns_an_773", "dns_an_774", "dns_an_775", "dns_an_776",
        "dns_an_777", "dns_an_778", "dns_an_779", "dns_an_780", "dns_an_781", "dns_an_782", "dns_an_783", "dns_an_784",
        "dns_an_785", "dns_an_786", "dns_an_787", "dns_an_788", "dns_an_789", "dns_an_790", "dns_an_791", "dns_an_792",
        "dns_an_793", "dns_an_794", "dns_an_795", "dns_an_796", "dns_an_797", "dns_an_798", "dns_an_799", "dns_an_800",
        "dns_an_801", "dns_an_802", "dns_an_803", "dns_an_804", "dns_an_805", "dns_an_806", "dns_an_807", "dns_an_808",
        "dns_an_809", "dns_an_810", "dns_an_811", "dns_an_812", "dns_an_813", "dns_an_814", "dns_an_815"
    ]
    header = ip_header + udp_header + dns_header
    header.append("label")
    # print(header)
    if line_length == 0:
        line_length = len(header)
    writer.writerow(header)
    if not (pcap_file.endswith(".pcap") or pcap_file.endswith(".PCAP")):
        print("\033[1;32m", "File " + pcap_file + " is not PCAP...Skipped.", "\033[0m")
        return
    pkts = rdpcap(pcap_file, count=packet_max_count)
    for pkt in pkts:
        # print(pkt.show())
        try:
            line = []
            ##############################################################
            ############################ IP ##############################
            ##############################################################
            if (IP not in pkt) or (UDP not in pkt) or (DNS not in pkt):
                continue
            # IP-version
            ip_version = pkt['IP'].fields['version']
            ip_version_formated = '{:04b}'.format(ip_version)
            for binary in ip_version_formated:
                line.append(int(binary))

            # IP-ihl
            ip_ihl = pkt['IP'].fields['ihl']
            ip_ihl_formated = '{:04b}'.format(ip_ihl)
            for binary in ip_ihl_formated:
                line.append(int(binary))

            # IP-tos
            ip_tos = pkt['IP'].fields['tos']
            ip_tos_formated = '{:08b}'.format(ip_tos)
            for binary in ip_tos_formated:
                line.append(int(binary))

            # IP-len
            ip_len = pkt['IP'].fields['len']
            ip_len_formated = '{:016b}'.format(ip_len)
            for binary in ip_len_formated:
                line.append(int(binary))

            # IP-id
            ip_id = pkt['IP'].fields['id']
            ip_id_formated = '{:016b}'.format(ip_id)
            for binary in ip_id_formated:
                line.append(int(binary))

            # IP-flags
            ip_flags = pkt['IP'].fields['flags']
            if ip_flags == "DF":
                ip_flags = 2
            elif ip_flags == "MF":
                ip_flags = 1
            else:
                ip_flags = 0
            ip_flags_formated = '{:03b}'.format(ip_flags)
            for binary in ip_flags_formated:
                line.append(int(binary))

            # IP-frag
            ip_frag = pkt['IP'].fields['frag']
            ip_frag_formated = '{:013b}'.format(ip_frag)
            for binary in ip_frag_formated:
                line.append(int(binary))

            # IP-ttl
            ip_ttl = pkt['IP'].fields['ttl']
            ip_ttl_formated = '{:08b}'.format(ip_ttl)
            for binary in ip_ttl_formated:
                line.append(int(binary))

            # IP-proto
            ip_proto = pkt['IP'].fields['proto']
            ip_proto_formated = '{:08b}'.format(ip_proto)
            for binary in ip_proto_formated:
                line.append(int(binary))

            # IP-chksum
            ip_chksum = pkt['IP'].fields['chksum']
            ip_chksum_formated = '{:016b}'.format(ip_chksum)
            for binary in ip_chksum_formated:
                line.append(int(binary))

            # IP-src
            ip_src = pkt['IP'].fields['src']
            ip_srcs = ip_src.split(".")
            for part in ip_srcs:
                part_formated = '{:08b}'.format(int(part))
                for binary in part_formated:
                    line.append(int(binary))

            # IP-dst
            ip_dst = pkt['IP'].fields['dst']
            ip_dsts = ip_dst.split(".")
            for part in ip_dsts:
                part_formated = '{:08b}'.format(int(part))
                for binary in part_formated:
                    line.append(int(binary))

            ##############################################################
            ############################ UDP ##############################
            ##############################################################
            if UDP not in pkt:
                continue
            # sport
            udp_sport = '{:016b}'.format(pkt['UDP'].fields['sport'])
            for udp_s in udp_sport:
                line.append(int(udp_s))
            # dport
            udp_dport = '{:016b}'.format(pkt['UDP'].fields['dport'])
            for udp_d in udp_dport:
                line.append(int(udp_d))
            # len
            udp_len = '{:016b}'.format(pkt['UDP'].fields['len'])
            for udp_l in udp_len:
                line.append(int(udp_l))
            # chksum
            udp_chksum = '{:016b}'.format(pkt['UDP'].fields['chksum'])
            for udp_c in udp_chksum:
                line.append(int(udp_c))

            ##############################################################
            ############################ DNS #############################
            ##############################################################
            if DNS not in pkt:
                continue
            # identifacation
            identifacation = '{:016b}'.format(pkt['DNS'].fields['id'])
            for dns_i in identifacation:
                line.append(int(dns_i))
            # qr
            qr = '{:01b}'.format(pkt['DNS'].fields['qr'])
            line.append(int(qr))

            # opcode
            opcode = '{:04b}'.format(pkt['DNS'].fields['opcode'])
            for op in opcode:
                line.append(int(op))

            # aa
            aa = '{:01b}'.format(pkt['DNS'].fields['aa'])
            line.append(int(aa))

            # tc
            tc = '{:01b}'.format(pkt['DNS'].fields['tc'])
            line.append(int(tc))

            # rd
            rd = '{:01b}'.format(pkt['DNS'].fields['rd'])
            line.append(int(rd))

            # ra
            ra = '{:01b}'.format(pkt['DNS'].fields['ra'])
            line.append(int(ra))

            # z
            z = '{:01b}'.format(pkt['DNS'].fields['z'])
            line.append(int(z))

            # ad
            ad = '{:01b}'.format(pkt['DNS'].fields['ad'])
            line.append(int(ad))

            # cd
            cd = '{:01b}'.format(pkt['DNS'].fields['cd'])
            line.append(int(cd))

            # rcode
            rcode = '{:04b}'.format(pkt['DNS'].fields['rcode'])
            for rc in rcode:
                line.append(int(rc))

            # qdcount
            qdcount = '{:016b}'.format(pkt['DNS'].fields['qdcount'])
            for qd in qdcount:
                line.append(int(qd))

            # ancount
            ancount = '{:016b}'.format(pkt['DNS'].fields['ancount'])
            for an in ancount:
                line.append(int(an))

            # nscount
            nscount = '{:016b}'.format(pkt['DNS'].fields['nscount'])
            for ns in nscount:
                line.append(int(ns))

            # arcount
            arcount = '{:016b}'.format(pkt['DNS'].fields['arcount'])
            for ar in arcount:
                line.append(int(ar))

            # qd
            if qd == None:
                for idx in range(800):
                    line.append((-1))
            else:
                # qd-qname
                qname = pkt['DNS'].fields['qd'].fields['qname']
                if qname == None:
                    for idx in range(768):
                        line.append((-1))
                else:
                    qname_encoded = encode_domain(qname)
                    for q_e in qname_encoded:
                        line.append(q_e)

                # qd-qtype
                try:
                    qtype = '{:016b}'.format(pkt['DNS'].fields['qd'].fields['qtype'])
                    for qt in qtype:
                        line.append(int(qt))
                except Exception as qtype_exception:
                    for qt in range(16):
                        line.append(int(-1))
                    print(f'qtype_exception:{qtype_exception}')

                # qd-qclass
                try:
                    qclass = '{:016b}'.format(pkt['DNS'].fields['qd'].fields['qclass'])
                    for qc in qclass:
                        line.append(int(qc))
                except Exception as qclass_excepttion:
                    print(f'qclass_excepttion:{qclass_excepttion}')
                    for qc in range(16):
                        line.append(int(-1))

            # an-rrname
            if pkt['DNS'].fields['an'] == None:
                for idx in range(816):
                    line.append(-1)
            else:
                # an-type
                type = '{:08b}'.format(pkt['DNS'].fields['an'].fields['type'])
                for t in type:
                    line.append(int(t))

                # an-rclass
                rclass = '{:08b}'.format(pkt['DNS'].fields['an'].fields['rclass'])
                for r in rclass:
                    line.append(int(r))

                # an-ttl
                ttl = '{:016b}'.format(pkt['DNS'].fields['an'].fields['ttl'])
                for tt in ttl:
                    line.append(int(tt))

                # an-rdlen
                if pkt['DNS'].fields['an'].fields['rdlen'] == None:
                    for idx in range(16):
                        line.append(-1)
                else:
                    rdlen = '{:016b}'.format(pkt['DNS'].fields['an'].fields['rdlen'])
                    for rd in rdlen:
                        line.append(int(rd))

                # an-rdata
                ip = pkt['DNS'].fields['an'].fields['rdata']
                if ip == None:
                    for idx in range(768):
                        line.append((-1))
                else:
                    ip_encoded = encode_domain(ip)
                    for i_e in ip_encoded:
                        line.append(i_e)

            ##############################################################
            ############################ Label ###########################
            ##############################################################
            line.append(label)

            if line_length != len(line):
                # pkt.show()
                print(header)
                print(line)
                print(line_length)
                print(len(line))
            writer.writerow(line)
        except Exception as e:
            print(f'except:{e}')
            continue


def check_int_list(lst):
    return all(isinstance(elem, int) for elem in lst)


if __name__ == '__main__':
    use_cuda = True
    device = torch.device("cuda" if (use_cuda and torch.cuda.is_available()) else "cpu")
    print("Current Device: " + str(device))
    # process_pcap_file_to_csv(
    # r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\data\CICBellDNS2021\Raw\spam\spam.pcap",
    # r"C:\Users\fanqi\Documents\GitHub\AutoDNS\Code\AutoDNS\data\CICBellDNS2021\Raw\spam\spam.pcap.csv", "spam", packet_max_count=-1, device=device)
    i=10000
    import time
    # 记录开始时间
    start_time = time.time()
    while (i>0):
        i=i-1
        encode_domain("www.caj2pdf.cn")
    end_time = time.time()
    # 计算运行时间（以秒为单位）
    run_time = end_time - start_time
    print("代码运行时间：", run_time, "秒")
