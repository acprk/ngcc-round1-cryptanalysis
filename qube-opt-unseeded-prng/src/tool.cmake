# Appended by run_all.sh to the COPIED optimized CMakeLists.txt (vendor tree untouched).
foreach(num 1 3 4 5)
  add_executable(qube-tool-${num} ${QUBE_TOOL_SRC})
  target_include_directories(qube-tool-${num} PRIVATE ${SRC_DIR}/x86/qube-${num} ${SRC_DIR}/common
      ${SRC_DIR}/x86 ${LIB_DIR}/fips202 ${LIB_DIR}/api_pkc ${LIB_DIR}/bitpolymul_x86 ${BENCHMARK_DIR})
  target_link_libraries(qube-tool-${num} PRIVATE core_opt_${num})
  set_target_properties(qube-tool-${num} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})
endforeach()
