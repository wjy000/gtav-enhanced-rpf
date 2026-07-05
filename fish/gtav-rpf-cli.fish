# GTAv RPF 文件解包命令
function gtav-rpf-extract
    if test (count $argv) -lt 1
        echo "用法: gtav-rpf-extract <rpf_path> [outpath]"
        return 1
    end

    set rpf_path $argv[1]
    set outpath $argv[2]
    if test -z "$outpath"
        set outpath (pwd)/out
    end

    set project_dir /Volumes/ext/projects/gtav-enhanced-rpf

    pushd $project_dir
    .venv/bin/python -m rpf_enhanced --aes-key keys/gtav_aes_key.dat extract $rpf_path -o $outpath
    popd
end

# GTAv RPF 文件信息查看
function gtav-rpf-info
    if test (count $argv) -lt 1
        echo "用法: gtav-rpf-info <rpf_path>"
        return 1
    end

    set rpf_path $argv[1]
    set project_dir /Volumes/ext/projects/gtav-enhanced-rpf

    pushd $project_dir
    .venv/bin/python -m rpf_enhanced --aes-key keys/gtav_aes_key.dat info $rpf_path
    popd
end

# GTAv RPF 文件列表
function gtav-rpf-list
    if test (count $argv) -lt 1
        echo "用法: gtav-rpf-list <rpf_path> [pattern]"
        return 1
    end

    set rpf_path $argv[1]
    set extra $argv[2..]
    set project_dir /Volumes/ext/projects/gtav-enhanced-rpf

    pushd $project_dir
    .venv/bin/python -m rpf_enhanced --aes-key keys/gtav_aes_key.dat list $rpf_path $extra
    popd
end

# GTAv RPF 文件目录树
function gtav-rpf-tree
    if test (count $argv) -lt 1
        echo "用法: gtav-rpf-tree <rpf_path> [-d N]"
        return 1
    end

    set rpf_path $argv[1]
    set extra $argv[2..]
    set project_dir /Volumes/ext/projects/gtav-enhanced-rpf

    pushd $project_dir
    .venv/bin/python -m rpf_enhanced --aes-key keys/gtav_aes_key.dat tree $rpf_path $extra
    popd
end