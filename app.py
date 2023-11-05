from src.network.machine import Machine

machine = Machine.create_machine_from_file("machine.txt")
machine.start()