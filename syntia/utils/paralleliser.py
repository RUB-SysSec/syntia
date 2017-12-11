import multiprocessing
from random import choice, shuffle


class Paralleliser(object):
    def __init__(self, commands, workers, number_of_tasks, task_groups, number_of_cpus=0):
        self.commands = commands
        self.workers = workers
        self.number_of_tasks = number_of_tasks
        self.task_groups = task_groups

        self.process_to_task_group = dict()
        self.process_to_task_id = dict()
        self.task_group_results = dict()

        if not number_of_cpus:
            number_of_cpus = multiprocessing.cpu_count()
        self.number_of_cpus = number_of_cpus

    def execute(self):
        # initialise parallel data structures
        manager = multiprocessing.Manager()
        results = manager.list()
        processes = [None] * self.number_of_tasks

        # set task_groups to not-finished
        task_group_states = {}
        for task in self.task_groups:
            task_group_states[task] = 0

        # initialise process mappings
        process_to_task_group = dict()
        process_to_index = dict()

        # initialise processes
        for i in range(len(processes)):
            # extend results
            results.append(None)

            # get command
            command = self.commands[i]

            # create process
            processes[i] = multiprocessing.Process(target=self.workers[i], args=(command, results, i))

            # map process to process index
            process_to_index[processes[i]] = i

            # choose task group randomly
            process_to_task_group[processes[i]] = self.task_groups[i]

        # initialise data structures
        active_processes = set()
        done = set()
        process_counter = -1

        # random permutation of process indexes
        random_process_indices = list(range(len(processes)))
        shuffle(random_process_indices)

        # iterate until all processes have been processed
        while len(done) < len(processes):
            # add more processes, if # processes < # cpu cores and there are processes remaining
            while len(active_processes) < self.number_of_cpus and process_counter < len(processes) - 1:
                # increase index
                process_counter += 1
                # random process index
                random_process_index = random_process_indices.pop()
                # get next process
                process = processes[random_process_index]

                # get process' task group
                task_group = process_to_task_group[process]

                # print random_process_index, task_group

                # process' taskgroup has been solved
                if task_group_states[task_group]:
                    done.add(process)

                # get next process
                if process in done:
                    continue

                # start process
                process.start()

                # add to active processes
                active_processes.add(process)

            # if there are active processes
            if active_processes:
                # choose random process
                process = choice(list(active_processes.copy()))

                # process has been terminated
                if not process.is_alive():
                    # get process index
                    process_index = process_to_index[process]
                    # get result
                    result = results[process_index]

                    # if process terminated with a result:
                    if result:
                        # get process' task group
                        task_group = process_to_task_group[process]
                        # set task group to finished
                        task_group_states[task_group] = 1

                        # store task group's result
                        self.task_group_results[task_group] = result

                        # terminate active processes in current task group
                        for process in active_processes.copy():
                            # process is in the same task group?
                            if task_group == process_to_task_group[process]:
                                # kill process
                                process.terminate()
                                # add to done
                                done.add(process)
                                # remove from active processes
                                active_processes.remove(process)

                    # delete process
                    else:
                        # add to done
                        done.add(process)
                        # remove from active processes
                        active_processes.remove(process)

        return results