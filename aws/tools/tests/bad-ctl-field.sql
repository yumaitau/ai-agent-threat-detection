-- negative control: CloudTrail Lake has no column "eventuser"; struct has no field "name"
SELECT eventuser, element_at(resources, 1).name FROM $EDS_ID WHERE eventTime > now();
