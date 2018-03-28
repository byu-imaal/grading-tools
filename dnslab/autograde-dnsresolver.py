#!/usr/bin/env python3
"""
To see usage, run ./autograde-dnsresolver -h

You must alter the submission code to talk to a selected instead of port 53!

Synopsis:
* For each domain name,
    * Query the real DNS server and store the request and the response
    * Run the submission on it and store the output.
* For each test output, check if they match the rubric (see main)
"""

import time
import re
import subprocess
from threading import Thread
import socket
from collections import namedtuple
import argparse
import sys
import dns.resolver
import binascii
import os
import logging

PROXY_MAX_READ_SIZE_BYTES = 8192

# If the submission exited with a nonzero exit code, the score for that
# test is multiplied by this factor.
# This usually happens with segfaults and the like.
EXITCODE_PENALTY = .5

# This sets the maximum partial credit percentage for a missed test.
# The actual value is a factor of how many lines they got right / total expected lines.
COMPARE_PARTIAL_CREDIT_MAX = .5

DEFAULT_DOMAINS = ['byu.edu', 'www.byu.edu', '.', 'casey.byu.edu', 'CASEY.byu.Edu', 'www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.com',
                   'sandia.gov', 'www.sandia.gov', 'foobarbaz-not-exist.byu.edu', 'www.intel.com']

SubmissionRunResult = namedtuple(
    'SubmissionRunResult', ['query_raw', 'stdout_raw', 'stderr_raw', 'exitcode'])

TestResult = namedtuple('TestResult', [
                        'qname', 'output', 'expected_output', 'query_raw', 'expected_query_raw', 'stderr_raw', 'exitcode'])


def parse_args():
    p = argparse.ArgumentParser(
        'DNS lab grader script that checks submissions by setting up a proxy dns server.')
    p.add_argument('-p', '--port', action='store', required=True,
                   type=int, help='[required] The port to run the dns proxy server on. Note that you must alter the submission code so that it sends queries to this port instead of port 53.')
    p.add_argument('-t', '--timeout', action='store', type=int,
                   default=2, help='Timeout, in seconds, for each test.')
    p.add_argument('-s', '--dns-server', action='store', type=str,
                   default='8.8.8.8', help='DNS server to proxy to.')
    p.add_argument('-d', '--domains', nargs='+', action='store', default=DEFAULT_DOMAINS,
                   help='Domains to query. You must include a cname, a root name, a nxdomain, and a normal domain.')
    p.add_argument('-v', action='store_true', default=False,
                   help='Verbose. Show all point assignments.')
    return p.parse_args()


def main():
    args = parse_args()

    test_input = args.domains

    # Run tests
    test_results = [x for x in run_tests(
        test_input, args.port, args.timeout, args.dns_server)]

    # The following is the point breakdown:
    # * 10 points for a well-formed DNS query message
    # * 10 points for successfully sending the query and receiving the response
    # * 20 points for successfully finding the answer in the answer section
    # * 5 points for handling CNAME records properly
    # * 5 points for handling names that don’t resolve
    # * 5 points for handling the root name properly
    # * 5 points for style
    # The maxmimum number of points is 60

    points = 0

    form_dns_query_points = 10
    send_and_receive_points = 10
    find_answer_in_response_points = 20
    cname_handle_points = 5
    nxdomain_handle_points = 5
    rootname_handle_points = 5

    max_points = form_dns_query_points + send_and_receive_points + find_answer_in_response_points + \
        cname_handle_points + nxdomain_handle_points + \
        rootname_handle_points

    next_points = do_form_dns_query_test(
        test_results, form_dns_query_points, args.v)
    print('awarding {} out of {} points.'.format(
        round(next_points, 2), form_dns_query_points))
    points += next_points

    next_points = do_send_and_receive_test(
        test_results, send_and_receive_points, args.v)
    print('awarding {} out of {} points.'.format(
        round(next_points, 2), send_and_receive_points))
    points += next_points

    next_points = do_find_answer_in_response_test(
        test_results, find_answer_in_response_points, args.v)
    print('awarding {} out of {} points.'.format(
        round(next_points, 2), find_answer_in_response_points))
    points += next_points

    next_points = do_cname_handle_test(
        test_results, cname_handle_points, args.v)
    print('awarding {} out of {} points.'.format(
        round(next_points, 2), cname_handle_points))
    points += next_points

    next_points = do_nxdomain_handle_test(
        test_results, nxdomain_handle_points, args.v)
    print('awarding {} out of {} points.'.format(
        round(next_points, 2), nxdomain_handle_points))
    points += next_points

    next_points = do_rootname_handle_test(
        test_results, rootname_handle_points, args.v)
    print('awarding {} out of {} points.'.format(
        round(next_points, 2), rootname_handle_points))
    points += next_points

    print('\n\n{} of {} points earned'.format(round(points, 2), max_points))
    return 0


def do_form_dns_query_test(test_results, form_dns_query_points, verbose):
    points = 0
    print('\n===== Testing for "a well-formed DNS query message" ({} points)...'.format(form_dns_query_points))

    test_results = only_normal_tests(test_results)
    for test, ratio, reason in test_properly_formed_query(test_results):
        next_points = ratio * form_dns_query_points / len(test_results)
        if verbose:
            print('{} points for test {}'.format(
                round(next_points, 2), test.qname))
        points += next_points
        if reason:
            print('Test {} failed'.format(test.qname))
            print(reason)
    return points


def do_send_and_receive_test(test_results, send_and_receive_points, verbose):
    """
    Finds the best score because the spec only requires that it work once.
    """
    print('\n===== Testing for "successfully sending the query and receiving the response" ({} points)...'.format(
        send_and_receive_points))
    points = 0
    max_ratio = 0
    max_reason = None

    for test, ratio, reason in test_send_receive(test_results):
        if ratio > max_ratio:
            max_ratio = ratio
            max_reason = reason

    points = max_ratio * send_and_receive_points
    if verbose:
        print('{} points for test {}'.format(
            round(points, 2), test.qname))

    if reason:
        print('Test {} failed'.format(test.qname))
        print(reason)

    return points


def do_find_answer_in_response_test(test_results, find_answer_in_response_points, verbose):
    points = 0
    print('\n===== Testing for "successfully finding the answer in the answer section" ({} points)...'.format(
        find_answer_in_response_points))

    normal_tests = only_normal_tests(test_results)

    if len(normal_tests) == 0:
        raise ValueError('No normal tests!')

    for test, ratio, reason in test_find_answer(normal_tests):
        next_points = ratio * \
            find_answer_in_response_points / len(normal_tests)
        if verbose:
            print('{} points for test {}'.format(
                round(next_points, 2), test.qname))
        points += next_points
        if reason:
            print('Test {} failed'.format(test.qname))
            print(reason)
    return points


def do_cname_handle_test(test_results, cname_handle_points, verbose):
    points = 0
    print('\n===== Testing for "handling CNAME records properly" ({} points)...'.format(
        cname_handle_points))
    cname_tests = only_cname_tests(test_results)

    if len(cname_tests) == 0:
        raise ValueError('No cname tests!')

    for test, ratio, reason in test_handle_cname(cname_tests):
        next_points = ratio * cname_handle_points / len(cname_tests)
        if verbose:
            print('{} points for test {}'.format(
                round(next_points, 2), test.qname))
        points += next_points
        if reason:
            print('Test {} failed'.format(test.qname))
            print(reason)
    return points


def do_nxdomain_handle_test(test_results, nxdomain_handle_points, verbose):
    points = 0
    print('\n===== Testing for "handling names that don’t resolve" ({} points)...'.format(
        nxdomain_handle_points))
    nxdomain_tests = only_nxdomain_tests(test_results)

    if len(nxdomain_tests) == 0:
        raise ValueError('No nxdomain tests!')

    for test, ratio, reason in test_handle_nxdomain(nxdomain_tests):
        next_points = ratio * nxdomain_handle_points / len(nxdomain_tests)
        if verbose:
            print('{} points for test {}'.format(
                round(next_points, 2), test.qname))
        points += next_points
        if reason:
            print('Test {} failed'.format(test.qname))
            print(reason)
    return points


def do_rootname_handle_test(test_results, rootname_handle_points, verbose):
    points = 0
    print('\n===== Testing for "handling the root name properly" ({} points)...'.format(
        rootname_handle_points))
    root_tests = only_root_tests(test_results)

    if len(root_tests) == 0:
        raise ValueError('No root tests!')

    for test, ratio, reason in test_handle_rootname(root_tests):
        next_points = ratio * rootname_handle_points / len(root_tests)
        if verbose:
            print('{} points for test {}'.format(
                round(next_points, 2), test.qname))
        points += next_points
        if reason:
            print('Test {} failed'.format(test.qname))
            print(reason)
    return points


def only_normal_tests(test_results):
    normal_tests = []
    for t in test_results:
        if is_cname_test(t):
            continue
        if is_nxdomain_test(t):
            continue
        if is_root_test(t):
            continue
        normal_tests.append(t)
    return normal_tests


def only_cname_tests(test_results):
    cname_tests = []
    for t in test_results:
        if not is_cname_test(t):
            continue
        cname_tests.append(t)
    return cname_tests


def only_nxdomain_tests(test_results):
    nxdomain_tests = []
    for t in test_results:
        if not is_nxdomain_test(t):
            continue
        nxdomain_tests.append(t)
    return nxdomain_tests


def only_root_tests(test_results):
    root_tests = []
    for t in test_results:
        if not is_root_test(t):
            continue
        root_tests.append(t)
    return root_tests

def non_root_tests(test_results):
    non_root_tests = []
    for t in test_results:
        if is_root_test(t):
            continue
        non_root_tests.append(t)
    return non_root_tests


def is_cname_test(test):
    return is_cname_singular(''.join(test.expected_output))


def is_cname_singular(record):
    return re.search('[^\d.]', record) != None


def is_nxdomain_test(test):
    return len(test.expected_output) == 0 and test.qname != '.'


def is_root_test(test):
    return test.qname == '.'


def test_properly_formed_query(test_results):
    for t in test_results:
        ratio, reason = compare(t.expected_output, t.output)

        if t.exitcode != 0:
            ratio = ratio * EXITCODE_PENALTY

        yield t, ratio, reason


def test_send_receive(test_results):
    for t in test_results:
        reason = None
        ratio = 1

        if len(t.query_raw) == 0:
            ratio = 0
            reason = 'The submission did not send any data.'
        
        if not reads_from_socket_in_strace(t.stderr_raw):
            ratio = 0
            reason = 'The submission did not receive any data from the socket.'

        if t.exitcode != 0:
            ratio = ratio * EXITCODE_PENALTY

        yield (t, ratio, reason)

def reads_from_socket_in_strace(stderr):
    if stderr == None:
        return False

    stderr = stderr.decode('utf-8', errors='replace')
    socket_call = re.search('\nsocket\([^=]*= (\d)\n', stderr)
    
    if socket_call is None:
        return False

    socket_fd = socket_call.group(1)
    read_call = re.search('\nread\({},'.format(socket_fd), stderr)

    return read_call is not None


def test_find_answer(test_results):
    for t in test_results:
        ratio, reason = compare(t.expected_output, t.output)

        if t.exitcode != 0:
            ratio = ratio * EXITCODE_PENALTY

        yield t, ratio, reason


def compare(expected_output, actual_output):
    reason = []
    ratio = 1

    expected = set(expected_output)
    actual = set(actual_output)

    intersection = expected.intersection(actual)
    missing = expected.difference(actual)
    extra = actual.difference(expected)

    if len(missing) != 0:
        ratio = 0
        reason.append('There are missing expected results')

    if len(extra) != 0:
        ratio = 0
        reason.append('There are extra actual results')

    if ratio == 0 and len(expected) > 0:
        # Get some points back if you have some answers
        ratio += COMPARE_PARTIAL_CREDIT_MAX * len(intersection) / len(expected)
        if ratio > 0:
            reason.append('Some points given back because {}/{} results are correct.'.format(
                len(intersection), len(expected)))

    if len(reason) == 0:
        reason = None
    else:
        reason = '* {}\nexpected: {},\nactual: {}\n'.format(
            '\n* '.join(reason), expected, actual)

    return ratio, reason


def test_handle_cname(test_results):
    for t in test_results:
        cname_expected = [x for x in t.expected_output if is_cname_singular(x)]
        cname_actual = [x for x in t.output if is_cname_singular(x)]

        ratio, reason = compare(cname_expected, cname_actual)

        if t.exitcode != 0:
            ratio = ratio * EXITCODE_PENALTY

        yield t, ratio, reason


def test_handle_nxdomain(test_results):
    for t in test_results:
        ratio, reason = compare(t.expected_output, t.output)

        if t.exitcode != 0:
            ratio = ratio * EXITCODE_PENALTY

        yield t, ratio, reason


def test_handle_rootname(test_results):
    for t in test_results:
        ratio, reason = compare(t.expected_output, t.output)

        # Special case since this is 0% correct.
        if t.exitcode != 0:
            ratio = 0

        yield t, ratio, reason


def run_tests(qnames, port, timeout, dns_server):

    for qname in qnames:
        print('running test on {}'.format(qname))
        canonical_query = get_canonical_query(qname)
        canonical_response = get_canonical_response(
            canonical_query, dns_server)

        result = run_submission_on_query(
            qname, canonical_response, port, timeout)

        submission_results = parse_submission_output(result.stdout_raw)
        expected_results = get_expected_results(canonical_response)

        normalize_result(submission_results)
        normalize_result(expected_results)

        yield TestResult(qname=qname, output=submission_results, expected_output=expected_results, query_raw=result.query_raw, expected_query_raw=canonical_query.to_wire(), stderr_raw=result.stderr_raw, exitcode=result.exitcode)


def normalize_result(result):
    for i in range(len(result)):
        result[i] = result[i].lower()
        if result[i][-1] == '.':
            continue
        if re.match('\d', result[i][-1]) != None:
            continue
        result[i] += '.'


def get_expected_results(response):
    results = []
    for cls in response.answer:
        for r in cls:
            results.append(str(r))

    return sorted(results)


def parse_submission_output(output):
    if not output:
        return []
    output = output.decode('utf-8', errors='replace')
    return [x for x in sorted(output.split('\n')) if x.strip() != '']


def get_canonical_query(qname):
    """
    Use dnspython to get query per spec.
    """
    return dns.message.make_query(qname, dns.rdatatype.A, use_edns=False)


def get_canonical_response(query_message, dns_server):
    """
    Send query to server and get response.
    """
    return dns.query.udp(query_message, dns_server)


def run_submission_on_query(qname, canonical_response, port, timeout):
    """
    Start proxy server on known port.
    """

    result = {}
    response = canonical_response.to_wire()
    thread = Thread(target=proxy_server, args=(
        '127.0.0.1', port, response, result, timeout))
    thread.start()

    run_result = subprocess.run(
        ['strace', './resolver', qname, '127.0.0.1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    thread.join(timeout)

    if thread.isAlive():
        print('Error testing submission: timeout in test {} after {} seconds!'.format(
            qname, timeout))

    return SubmissionRunResult(query_raw=result.get('request', ''), stdout_raw=run_result.stdout or b'', stderr_raw=run_result.stderr or b'', exitcode=run_result.returncode)
    # For testing reporting:
    # return SubmissionRunResult(query_raw=b'', stdout_raw=b'', stderr_raw=b'hello there', exitcode=1)


def proxy_server(ip, port, response, result, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sa = (ip, port)
    sock.bind(sa)
    try:
        request, address = sock.recvfrom(PROXY_MAX_READ_SIZE_BYTES)
    except socket.timeout:
        print('test timed out!')
        return
    result['request'] = request
    sock.sendto(response, address)
    sock.close()


if __name__ == '__main__':
    exit(main())
