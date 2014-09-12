=========
mptctrace
=========

mptcptrace analyze MPTCP traces

Reference
=========

If you plan to use this tool in a publication, please use the following reference:

.. code-block:: console

        @inproceedings{Hesmans:2014:TMT:2619239.2631453,
         author = {Hesmans, Benjamin and Bonaventure, Olivier},
         title = {Tracing Multipath TCP Connections},
         booktitle = {Proceedings of the 2014 ACM Conference on SIGCOMM},
         series = {SIGCOMM '14},
         year = {2014},
         isbn = {978-1-4503-2836-4},
         location = {Chicago, Illinois, USA},
         pages = {361--362},
         numpages = {2},
         url = {http://doi.acm.org/10.1145/2619239.2631453},
         doi = {10.1145/2619239.2631453},
         acmid = {2631453},
         publisher = {ACM},
         address = {New York, NY, USA},
         keywords = {Multipath TCP},
        } 


Building
========

You can build mptctrace with:

.. code-block:: console

        $ ./autogen
        $ ./configure --prefix=whatever/
        $ make
        $ make install

I you have troubles to compile it, you can contact me.

Use it
======

You need to provide a pcap trace to mptctrace with the ``-f`` option. Mptcptrace will recognize ETH and Linux cooked header, if it's something else, you can use "-o" to tell mptctrace the offset to go to the IP header.

There is manpage in the man directory.

To get started you can try the ``-s`` option that will output MPTCP sequence graph:

.. code-block:: console

        $ mptcptrace -f myDump.pcap -s

This will generate 2 xplot files for each MPTCP connection inside the trace (one to show sequences numbers from client to server (c2s) and the other to show sequences numbers from the server to the client (s2c)).


