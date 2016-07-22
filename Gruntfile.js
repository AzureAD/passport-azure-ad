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
  grunt.registerTask('run_all_tests', ['printMsg_chai-passport', 'mochaTest', 'printMsg_nodeunit', 'nodeunit']);
  grunt.registerTask('default', 'run_all_tests');
};
