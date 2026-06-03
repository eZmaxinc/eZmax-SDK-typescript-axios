# UserRequest

A User Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiAgentID** | **number** | The unique ID of the Agent. | [optional] [default to undefined]
**fkiBrokerID** | **number** | The unique ID of the Broker. | [optional] [default to undefined]
**fkiAssistantID** | **number** | The unique ID of the Assistant. | [optional] [default to undefined]
**fkiEmployeeID** | **number** | The unique ID of the Employee. | [optional] [default to undefined]
**fkiCompanyIDDefault** | **number** | The unique ID of the Company | [default to undefined]
**fkiDepartmentIDDefault** | **number** | The unique ID of the Department | [default to undefined]
**fkiTimezoneID** | **number** | The unique ID of the Timezone | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**objEmail** | [**EmailRequestCompound**](EmailRequestCompound.md) |  | [default to undefined]
**fkiBillingentityinternalID** | **number** | The unique ID of the Billingentityinternal. | [default to undefined]
**objPhoneHome** | [**PhoneRequestCompound**](PhoneRequestCompound.md) |  | [optional] [default to undefined]
**objPhoneSMS** | [**PhoneRequestCompound**](PhoneRequestCompound.md) |  | [optional] [default to undefined]
**fkiSecretquestionID** | **number** | The unique ID of the Secretquestion.  Valid values:  |Value|Description| |-|-| |1|The name of the hospital in which you were born| |2|The name of your grade school| |3|The last name of your favorite teacher| |4|Your favorite sports team| |5|Your favorite TV show| |6|Your favorite movie| |7|The name of the street on which you grew up| |8|The name of your first employer| |9|Your first car| |10|Your favorite food| |11|The name of your first pet| |12|Favorite musician/band| |13|What instrument you play| |14|Your father\&#39;s middle name| |15|Your mother\&#39;s maiden name| |16|Name of your eldest child| |17|Your spouse\&#39;s middle name| |18|Favorite restaurant| |19|Childhood nickname| |20|Favorite vacation destination| |21|Your boat\&#39;s name| |22|Date of Birth (YYYY-MM-DD)| |23|Secret Code| |24|Your reference code| |25|What are the last 4 digits of your SIN| |26|What is your postal code| |27|What is your employee number| |28|What is your manager’s first name| |29|What is your file number| |30|What is your client/member number| |31|What is your license number| |32|What are the last 4 digits of your phone number| |33|What is your student number| | [optional] [default to undefined]
**sUserSecretresponse** | **string** | The answer to the Secretquestion | [optional] [default to undefined]
**fkiModuleIDForm** | **number** | The unique ID of the Module | [optional] [default to undefined]
**eUserType** | [**FieldEUserType**](FieldEUserType.md) |  | [default to undefined]
**eUserLogintype** | [**FieldEUserLogintype**](FieldEUserLogintype.md) |  | [default to undefined]
**sUserFirstname** | **string** | The first name of the user | [default to undefined]
**sUserLastname** | **string** | The last name of the user | [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [default to undefined]
**sUserJobtitle** | **string** | The job title of the user | [optional] [default to undefined]
**eUserEzsignaccess** | [**FieldEUserEzsignaccess**](FieldEUserEzsignaccess.md) |  | [default to undefined]
**bUserIsactive** | **boolean** | Whether the User is active or not | [default to undefined]
**bUserValidatebyadministration** | **boolean** | Whether if the transactions in which the User is implicated must be validated by administrative personnel or not | [optional] [default to undefined]
**bUserValidatebydirector** | **boolean** | Whether if the transactions in which the User is implicated must be validated by a director or not | [optional] [default to undefined]
**bUserAttachmentautoverified** | **boolean** | Whether if Attachments uploaded by the User must be validated or not | [optional] [default to undefined]
**bUserChangepassword** | **boolean** | Whether if the User is forced to change its password | [optional] [default to undefined]
**bUserEzsigntemplaterolegrouping** | **boolean** | Whether we group or not the Ezsigntemplate roles | [optional] [default to undefined]

## Example

```typescript
import { UserRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UserRequest = {
    pkiUserID,
    fkiAgentID,
    fkiBrokerID,
    fkiAssistantID,
    fkiEmployeeID,
    fkiCompanyIDDefault,
    fkiDepartmentIDDefault,
    fkiTimezoneID,
    fkiLanguageID,
    objEmail,
    fkiBillingentityinternalID,
    objPhoneHome,
    objPhoneSMS,
    fkiSecretquestionID,
    sUserSecretresponse,
    fkiModuleIDForm,
    eUserType,
    eUserLogintype,
    sUserFirstname,
    sUserLastname,
    sUserLoginname,
    sUserJobtitle,
    eUserEzsignaccess,
    bUserIsactive,
    bUserValidatebyadministration,
    bUserValidatebydirector,
    bUserAttachmentautoverified,
    bUserChangepassword,
    bUserEzsigntemplaterolegrouping,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
