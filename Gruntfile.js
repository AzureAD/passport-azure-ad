'use strict';

module.exports = function loadGrunt(grunt) {
  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    nodeunit: {
      files: ['test/Nodeunit_test/*_test.js'],
    },
    mochaTest: {
      test: {
        options: {
          reporter: 'spec',
          clearRequireCache: true
        },
        src: ['test/Chai-passport_test/*_test.js'],
      },
    },
    eslint: {
      options: {},
      gruntfile: {
        src: 'Gruntfile.js',
      },
      lib: {
        src: ['lib/**/*.js'],
      },
      examples: {
        src: ['examples/*/*.js'],
      },
      test: {
        src: ['test/**/*.js'],
      },
    },
    watch: {
      gruntfile: {
        files: '<%= eslint.gruntfile.src %>',
        tasks: ['eslint:gruntfile'],
      },
      lib: {
        files: '<%= eslint.lib.src %>',
        tasks: ['eslint:lib', 'nodeunit', 'mochaTest'],
      },
      test: {
        files: '<%= eslint.test.src %>',
        tasks: ['eslint:test', 'nodeunit', 'mochaTest'],
      },
    },
  });

  // These plugins provide necessary tasks.
  grunt.loadNpmTasks('grunt-contrib-nodeunit');
  grunt.loadNpmTasks('grunt-eslint');
  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-mocha-test');

  grunt.registerTask('printMsg_nodeunit', () => {
    grunt.log.writeln('\n\n\n======= Running tests in test/nodeunit_test =======\n\n\n');
  });
  grunt.registerTask('printMsg_chai-passport', () => {
    grunt.log.writeln('\n\n\n======= Running tests in test/chai-passport_test =======\n\n\n');
  });
  grunt.registerTask('printMsg_end_to_end_Test', () => {
    grunt.log.writeln('\n\n\n======= Running end to end tests in test/End_to_end_test =======\n\n\n');
  });

  var run_e2e_tests = (process.version >= 'v6.9');

  grunt.registerTask('end_to_end_test', () => {
    if (run_e2e_tests) {
      grunt.config('mochaTest.test.src', 'test/End_to_end_test/*_test.js');
      grunt.task.run(['mochaTest']);
    } else {
      grunt.log.writeln('\n\n\n======= No end to end tests for node version < v6.9 =======\n\n\n');
    }
  });
  grunt.registerTask('run_all_tests', ['printMsg_chai-passport', 'mochaTest', 'printMsg_nodeunit', 'nodeunit', 'printMsg_end_to_end_Test', 'end_to_end_test']);
  grunt.registerTask('default', 'run_all_tests');
};
