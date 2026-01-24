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
**sProvinceNameX** | **string** | The name of the Province in the language of the requester | [optional] [default to undefined]
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
    sProvinceNameX,
    sCountryNameX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
