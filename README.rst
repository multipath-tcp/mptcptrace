=========
mptctrace
=========

mptcptrace analyze MPTCP traces

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


