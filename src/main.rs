use datetime::*;
use rot13::{rot13_slice, Mode};
use std::io;
use std::time::Duration;
use winreg::enums::*;
use winreg::*;

fn main() -> io::Result<()> {
    println!("--------------- Execution analysis ---------------\n");
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    println!("--------------------- Run MRU --------------------");
    let _is_run_mru_activated =
        hkcu.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced")?;
    let is_runmru_activated: u32 = _is_run_mru_activated.get_value("Start_TrackProgs").unwrap();
    println!("Programs tracking is enable : {}", is_runmru_activated >= 1);
    let run_mru =
        hkcu.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")?;
    println!("The following values were found:");
    for (name, value) in run_mru.enum_values().map(|x| x.unwrap()) {
        if name == "MRUList" {
            continue;
        }
        let tmp = value.to_string()[1..].to_string();
        let pos = tmp.to_string().find("\\").unwrap();
        println!("{}", tmp.to_string().split_at(pos).0);
    }

    println!("------------------ User Assist  ------------------");
    let user_assist =
        hkcu.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")?;
    for guid in user_assist.enum_keys().map(|x| x.unwrap()) {
        if !guid.contains("CEBFF5CD-ACE2-4F4F-9178-9926F41749EA") {
            continue;
        }
        let count = user_assist
            .open_subkey(format!("{}{}", guid, "\\Count"))
            .unwrap();
        for (name, value) in count.enum_values().map(|x| x.unwrap()) {
            let mut decrpted_str =
                String::from_utf8(rot13_slice(Mode::Decrypt, name.as_bytes())).unwrap();
            // src https://www.aldeid.com/wiki/Windows-userassist-keys
            if decrpted_str.contains("F38BF404-1D43-42F2-9305-67DE0B28FC23") {
                decrpted_str =
                    decrpted_str.replace("F38BF404-1D43-42F2-9305-67DE0B28FC23", "Windows");
            } else if decrpted_str.contains("1AC14E77-02E7-4E5D-B744-2EB1AE5198B7") {
                decrpted_str =
                    decrpted_str.replace("1AC14E77-02E7-4E5D-B744-2EB1AE5198B7", "system32");
            } else if decrpted_str.contains("9E3995AB-1F9C-4F13-B827-48B24B6C7174") {
                decrpted_str = decrpted_str.replace(
                    "9E3995AB-1F9C-4F13-B827-48B24B6C7174",
                    "Microsoft\\Windows\\Start Menu\\Programs",
                );
            } else if decrpted_str.contains("0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8") {
                decrpted_str = decrpted_str.replace(
                    "0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8",
                    "Quick Launch\\User Pinned",
                );
            }
            println!("{}", decrpted_str);
            let run_counter = slice_to_u32(&value.bytes[4..8]);
            let focus_count = slice_to_u32(&value.bytes[8..12]);
            let timestamps = slice_to_u64(&value.bytes[60..68]);
            let focus_time = slice_to_u32(&value.bytes[12..16]) / 1000;
            let focus_time_s = focus_time % 60;
            let focus_time_h = (focus_time - focus_time_s) / 3600;
            let focus_time_m = ((focus_time - focus_time_s) % 3600) / 60;
            println!("run counter\t: {}", run_counter);
            println!("focus counter\t: {}", focus_count);
            println!("focus counter\t: {}", focus_time);
            println!(
                "focus time\t: {}h {}m {}s",
                focus_time_h, focus_time_m, focus_time_s
            );
            
            if timestamps == 0 {
                println!("Program was not executed.");
            } else {
                println!("Last execution\t: {}", rawvalue_to_timestamp(timestamps));
            }
            println!()
        }
    }
    Ok(())
}

pub fn slice_to_u32(array: &[u8]) -> u32 {
    let tmp: [u8; 4] = array.try_into().unwrap();
    u32::from_le_bytes(tmp.try_into().unwrap())
}

pub fn slice_to_u64(array: &[u8]) -> u64 {
    let tmp: [u8; 8] = array.try_into().unwrap();
    u64::from_le_bytes(tmp.try_into().unwrap())
}

pub fn rawvalue_to_timestamp(tmp: u64) -> String {
    let nanos_to_secs: i64 = Duration::from_nanos(tmp * 100)
        .as_secs()
        .try_into()
        .unwrap();
    let windows_base_date = LocalDate::ymd(1601, Month::January, 1).unwrap();
    let windows_base_time = LocalTime::hm(0i8, 0i8).unwrap();
    let windows_base_timestamp = LocalDateTime::new(windows_base_date, windows_base_time);
    let mut string_vec: Vec<String> = Vec::new();
    windows_base_timestamp
        .add_seconds(nanos_to_secs)
        .iso()
        .to_string()
        .split("T")
        .for_each(|x| string_vec.push(x.to_string()));
    format!(
        "{} {}",
        string_vec.get(0).unwrap(),
        string_vec.get(1).unwrap()
    )
}
