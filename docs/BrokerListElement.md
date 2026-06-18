# BrokerListElement

A Broker List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiBrokerID** | **number** | The unique ID of the Broker. | [default to undefined]
**fkiDepartmentID** | **number** | The unique ID of the Department | [default to undefined]
**sDepartmentNameX** | **string** | The Name of the Department in the language of the requester | [optional] [default to undefined]
**fkiBrokertypeID** | **number** | The unique ID of the Brokertype | [default to undefined]
**sBrokertypeNameX** | **string** | The name of the Brokertype in the language of the requester | [default to undefined]
**sBrokerCode** | **string** | The code of the Broker | [default to undefined]
**sRealestateboardnumberNumber** | **string** | The number of the Realestateboardnumber | [optional] [default to undefined]
**iAgentBannernumber** | **number** | The bannernumber of the Agent | [optional] [default to undefined]
**sLanguageNameX** | **string** | The Name of the Language in the language of the requester | [optional] [default to undefined]
**iBrokerPhotocopiercode** | **number** | The photocopiercode of the Broker | [default to undefined]
**iBrokerLongdistancecode** | **number** | The longdistancecode of the Broker | [default to undefined]
**sBrokerName** | **string** | The name of the Broker | [default to undefined]
**sBrokerRealestateassociationlicense** | **string** | The realestateassociationlicense of the Broker | [default to undefined]
**dtBrokerHiredate** | **string** | The hiredate of the Broker | [default to undefined]
**dtBrokerLeavedate** | **string** | The leavedate of the Broker | [optional] [default to undefined]
**bBrokerTranquillit** | **boolean** | Whether if it\&#39;s an tranquillit | [optional] [default to undefined]
**bBrokerResidentiallicense** | **boolean** | Whether if it\&#39;s an residentiallicense | [default to undefined]
**bBrokerCommerciallicense** | **boolean** | Whether if it\&#39;s an commerciallicense | [default to undefined]
**bBrokerMortgagelicense** | **boolean** | Whether if it\&#39;s an mortgagelicense | [default to undefined]
**bBrokerPaidbyofficetranquillit** | **boolean** | Whether if it\&#39;s an paidbyofficetranquillit | [default to undefined]
**dtBrokerFintraccertification** | **string** | The fintraccertification of the Broker | [optional] [default to undefined]
**bBrokerIsactive** | **boolean** | Whether the Broker is active or not | [default to undefined]
**sContactFirstname** | **string** | The First name of the contact | [optional] [default to undefined]
**sContactLastname** | **string** | The Last name of the contact | [optional] [default to undefined]
**dtContactBirthdate** | **string** | The Birth Date of the contact | [optional] [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**sPhoneE164** | **string** | A phone number in E.164 Format | [optional] [default to undefined]
**sAddressCivic** | **string** | The Civic number. | [optional] [default to undefined]
**sAddressStreet** | **string** | The Street Name | [optional] [default to undefined]
**sAddressSuite** | **string** | The Suite or appartment number | [optional] [default to undefined]
**sAddressCity** | **string** | The City name | [optional] [default to undefined]
**sAddressZip** | **string** | The Postal/Zip Code  The value must be entered without spaces | [optional] [default to undefined]
**fkiProvinceID** | **number** | The unique ID of the Province.  Here are some common values (Complete list must be retrieved from API):  |Value|Description| |-|-| |1|(Canada) Alberta |2|(Canada) British Columbia| |3|(Canada) Manitoba| |3|(Canada) Manitoba| |4|(Canada) New Brunswick| |5|(Canada) Newfoundland| |6|(Canada) Northwest Territories| |7|(Canada) Nova Scotia| |8|(Canada) Nunavut| |9|(Canada) Ontario| |10|(Canada) Prince Edward Island| |11|(Canada) Quebec| |12|(Canada) Saskatchewan| |13|(Canada) Yukon| |14|(United-States) Alabama| |15|(United-States) Alaska| |16|(United-States) Arizona| |17|(United-States) Arkansas| |18|(United-States) California| |19|(United-States) Colorado| |20|(United-States) Connecticut| |21|(United-States) Delaware| |22|(United-States) District of Columbia| |23|(United-States) Florida| |24|(United-States) Georgia| |25|(United-States) Hawaii| |26|(United-States) Idaho| |27|(United-States) Illinois| |28|(United-States) Indiana| |29|(United-States) Iowa| |30|(United-States) Kansas| |31|(United-States) Kentucky| |32|(United-States) Louisiane| |33|(United-States) Maine| |34|(United-States) Maryland| |35|(United-States) Massachusetts| |36|(United-States) Michigan| |37|(United-States) Minnesota| |38|(United-States) Mississippi| |39|(United-States) Missouri| |40|(United-States) Montana| |41|(United-States) Nebraska| |42|(United-States) Nevada| |43|(United-States) New Hampshire| |44|(United-States) New Jersey| |45|(United-States) New Mexico| |46|(United-States) New York| |47|(United-States) North Carolina| |48|(United-States) North Dakota| |49|(United-States) Ohio| |50|(United-States) Oklahoma| |51|(United-States) Oregon| |52|(United-States) Pennsylvania| |53|(United-States) Rhode Island| |54|(United-States) South Carolina| |55|(United-States) South Dakota| |56|(United-States) Tennessee| |57|(United-States) Texas| |58|(United-States) Utah| |60|(United-States) Vermont| |59|(United-States) Virginia| |61|(United-States) Washington| |62|(United-States) West Virginia| |63|(United-States) Wisconsin| |64|(United-States) Wyoming| | [optional] [default to undefined]
**sProvinceNameX** | **string** | The name of the Province in the language of the requester | [optional] [default to undefined]
**fkiCountryID** | **number** | The unique ID of the Country.  Here are some common values (Complete list must be retrieved from API):  |Value|Description| |-|-| |1|Canada| |2|United-States| | [optional] [default to undefined]
**sCountryNameX** | **string** | The name of the Country in the language of the requester | [optional] [default to undefined]

## Example

```typescript
import { BrokerListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BrokerListElement = {
    pkiBrokerID,
    fkiDepartmentID,
    sDepartmentNameX,
    fkiBrokertypeID,
    sBrokertypeNameX,
    sBrokerCode,
    sRealestateboardnumberNumber,
    iAgentBannernumber,
    sLanguageNameX,
    iBrokerPhotocopiercode,
    iBrokerLongdistancecode,
    sBrokerName,
    sBrokerRealestateassociationlicense,
    dtBrokerHiredate,
    dtBrokerLeavedate,
    bBrokerTranquillit,
    bBrokerResidentiallicense,
    bBrokerCommerciallicense,
    bBrokerMortgagelicense,
    bBrokerPaidbyofficetranquillit,
    dtBrokerFintraccertification,
    bBrokerIsactive,
    sContactFirstname,
    sContactLastname,
    dtContactBirthdate,
    sEmailAddress,
    sPhoneE164,
    sAddressCivic,
    sAddressStreet,
    sAddressSuite,
    sAddressCity,
    sAddressZip,
    fkiProvinceID,
    sProvinceNameX,
    fkiCountryID,
    sCountryNameX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
