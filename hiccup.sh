#!/bin/sh

BURP_PACKAGE="";

BURP_COUNT=`ls burpsuite_*.jar | wc -l`;

if [ $BURP_COUNT = 1 ]; then
    BURP_PACKAGE=`ls burpsuite_*.jar`;
else
    for i in ls burpsuite_*.jar; do
        if [ -e ${i} ]; then
            echo "Found ${BURP_COUNT#"${BURP_COUNT%%[![:space:]]*}"} Burp packages; use ${i}? (y/n): \c"
            read answer
            case ${answer} in
                y*|Y*) BURP_PACKAGE=${i}; break;  ;;
                n*|N*) ;;
                *) : ;;
            esac
        fi
    done
fi

if [ "x$BURP_PACKAGE" == "x" ]; then
    echo "ERROR: A necessary Burp Suite package could not be located, or was not selected; view README file, or download from http://portswigger.net/burp/download.html.";
    exit 1;
fi

java -Xmx1024m -classpath $BURP_PACKAGE:lib/BurpExtender.jar:lib/sqlitejdbc-v056.jar -Dpython.path=$PWD:$PWD/lib:$PWD/hiccup:$PWD/plugins burp.StartBurp
