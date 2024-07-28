mkdir bcc/build && cd bcc/build && \
      cmake .. && \
      make install && \
      cmake -DPYTHON_CMD=python3 .. && \
      cd src/python/ && \
      make && \
      make install && \
      cd ../..
