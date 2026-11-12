add_executable(ai_ran_decode_e2 decode-payload.c)
target_link_libraries(ai_ran_decode_e2 PRIVATE e2ap_asn1_obj m)

add_executable(ai_ran_decode_rc decode-payload.c)
target_compile_definitions(ai_ran_decode_rc PRIVATE AI_RAN_RC)
target_link_libraries(ai_ran_decode_rc PRIVATE e2sm_rc_asn1_obj m)
