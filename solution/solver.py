from glob import glob


# Function to find the process file that contains a particular string.
# Returns the pid as well as the position of the string in the file.
def find(text):
    for path in glob("trace.*"):
        with open(path) as f:
            position = f.read().find(text)
            if position != -1:
                return path.split(".")[-1], position

    return None, None


# Locate the starting process.
previous, _ = find("Incorrect")
order = []

# Following the parent enough times at the end to extract the full program.
with open(f"trace.{previous}") as f:
    parent_times = f.read().count("fork()")

order += ["parent"] * parent_times

# Looping until the start of the program.
while True:
    current, position = find(previous)

    # Nowhere left to go. Must be the start of the program.
    if current is None:
        break

    # The number of forks before the fork that takes the correct path
    # is the number of times to follow the parent process.
    with open(f"trace.{current}") as f:
        parent_times = f.read().count("fork()", 0, position) - 1

    order.append("child")  # Follow the fork that takes the correct path.
    order += ["parent"] * parent_times

    previous = current

# Initial setup to enable logging and set a breakpoint berore the call.
output = """set disassembly-flavor intel
set logging on
b *0x8049fdb
r < /dev/random
ni
x/i $pc
set follow-fork-mode """

# Continue to the breakpoint. Advance. Examine the function. Follow correctly.
output += """
c
ni
x/i $pc
set follow-fork-mode """.join(order[::-1])
output += """
c
ni
x/i $pc
"""

print(output)
