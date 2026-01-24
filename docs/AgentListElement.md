# AgentListElement

A Agent List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiAgentID** | **number** | The unique ID of the Agent. | [default to undefined]
**fkiAgenttypeID** | **number** | The unique ID of the Agenttype | [default to undefined]
**sAgenttypeNameX** | **string** | The name of the Agenttype in the language of the requester | [default to undefined]
**fkiAgentincorporationID** | **number** | The unique ID of the Agentincorporation. | [optional] [default to undefined]
**sAgentincorporationName** | **string** | The name of the Agentincorporation | [optional] [default to undefined]
**fkiDepartmentID** | **number** | The unique ID of the Department | [default to undefined]
**sDepartmentNameX** | **string** | The Name of the Department in the language of the requester | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sLanguageNameX** | **string** | The Name of the Language in the language of the requester | [default to undefined]
**sRealestateboardnumberNumber** | **string** | The number of the Realestateboardnumber | [optional] [default to undefined]
**sAgentCode** | **string** | The code of the Agent | [default to undefined]
**iAgentPhotocopiercode** | **number** | The photocopiercode of the Agent | [default to undefined]
**iAgentLongdistancecode** | **number** | The longdistancecode of the Agent | [default to undefined]
**iAgentBannernumber** | **number** | The bannernumber of the Agent | [default to undefined]
**sAgentRealestateassociationlicense** | **string** | The realestateassociationlicense of the Agent | [default to undefined]
**dtAgentHiredate** | **string** | The hiredate of the Agent | [optional] [default to undefined]
**dtAgentLeavedate** | **string** | The leavedate of the Agent | [optional] [default to undefined]
**bAgentTranquillit** | **boolean** | Whether if it\&#39;s an tranquillit | [default to undefined]
**bAgentResidentiallicense** | **boolean** | Whether if it\&#39;s an residentiallicense | [default to undefined]
**bAgentCommerciallicense** | **boolean** | Whether if it\&#39;s an commerciallicense | [default to undefined]
**bAgentMortgagelicense** | **boolean** | Whether if it\&#39;s an mortgagelicense | [default to undefined]
**bAgentPaidbyofficetranquillit** | **boolean** | Whether if it\&#39;s an paidbyofficetranquillit | [default to undefined]
**dtAgentFintraccertification** | **string** | The fintraccertification of the Agent | [optional] [default to undefined]
**bAgentIsactive** | **boolean** | Whether the Agent is active or not | [default to undefined]
**sContactFirstname** | **string** | The First name of the contact | [default to undefined]
**sContactLastname** | **string** | The Last name of the contact | [default to undefined]
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
import { AgentListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AgentListElement = {
    pkiAgentID,
    fkiAgenttypeID,
    sAgenttypeNameX,
    fkiAgentincorporationID,
    sAgentincorporationName,
    fkiDepartmentID,
    sDepartmentNameX,
    fkiLanguageID,
    sLanguageNameX,
    sRealestateboardnumberNumber,
    sAgentCode,
    iAgentPhotocopiercode,
    iAgentLongdistancecode,
    iAgentBannernumber,
    sAgentRealestateassociationlicense,
    dtAgentHiredate,
    dtAgentLeavedate,
    bAgentTranquillit,
    bAgentResidentiallicense,
    bAgentCommerciallicense,
    bAgentMortgagelicense,
    bAgentPaidbyofficetranquillit,
    dtAgentFintraccertification,
    bAgentIsactive,
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
