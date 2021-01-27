#/usr/bin/env python

import os
import tqdm
import logging
import re
import csv

from argparse import ArgumentParser, RawTextHelpFormatter
from textwrap import dedent

from episurfsr.log_utils import getLogger


DESC = dedent(
    """
    Read log file from BasicSR inference and extract datasets and corresponding metrics as csv.
    """
)
EPILOG = dedent(
    """
    Example call:
      {filename} -i /path/to/log/file -o /path/to/output/csv
    """.format(
        filename=os.path.basename(__file__)
    )
)


def build_argparser():

    p = ArgumentParser(
        description=DESC, epilog=EPILOG, formatter_class=RawTextHelpFormatter
    )
    p.add_argument(
        "-i",
        "--logfile",
        required=True,
        help="Path to logfile from BasicSR inference.",
    )
    p.add_argument(
        "-o",
        "--csvfile",
        required=True,
        help="Path to output CSV file with results for each tested dataset.",
    )

    return p


if __name__ == "__main__":

    # get command line arguments
    p = build_argparser()
    args = vars(p.parse_args())

    logger = getLogger(name=os.path.basename(__file__))

    logging.info(
        "Reading results from '{logfile}' and writing them to '{csvfile}'.".format(
            logfile=args['logfile'], csvfile=args['csvfile']
        )
    )

    # read the log file
    with open(args['logfile'], 'r') as f:
        text = f.read()

    # Example:
    #
    # 2021-01-27 21:42:07,159 INFO: Validation coronal3
    #   # psnr: 33.5907
    #   # ssim: 0.8770

    # extract the info and write as csv
    regex_full = r"INFO: Validation (?P<dataset>.*)\n.*# psnr: (?P<psnr>\d+\.\d+)\n.*# ssim: (?P<ssim>\d+\.\d+)$"

    with open(args['csvfile'], 'w', newline='') as csvfile:
        fieldnames = ['dataset', 'psnr', 'ssim']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        # extract the information
        matches = list(re.finditer(regex_full, text, re.MULTILINE))
        matches = sorted(matches, key=lambda x: x['dataset'])

        for m in tqdm.tqdm(
            matches,
            desc="Looping over datasets"
        ):
            if m:
                writer.writerow(m.groupdict())

    logging.info("Done.")
