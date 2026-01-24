# CustomEzsignformfieldgroupCreateEzsignelementsPositionedByWordRequest

An Ezsignformfieldgroup Object in the context of a createEzsignelementsPositionedByWord path

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignformfieldgroupID** | **number** | The unique ID of the Ezsignformfieldgroup | [optional] [default to undefined]
**fkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**eEzsignformfieldgroupType** | [**FieldEEzsignformfieldgroupType**](FieldEEzsignformfieldgroupType.md) |  | [default to undefined]
**eEzsignformfieldgroupSignerrequirement** | [**FieldEEzsignformfieldgroupSignerrequirement**](FieldEEzsignformfieldgroupSignerrequirement.md) |  | [optional] [default to undefined]
**sEzsignformfieldgroupLabel** | **string** | The Label for the Ezsignformfieldgroup | [default to undefined]
**iEzsignformfieldgroupStep** | **number** | The step when the Ezsignsigner will be invited to fill the form fields | [default to undefined]
**sEzsignformfieldgroupDefaultvalue** | **string** | The default value for the Ezsignformfieldgroup  You can use the codes below and they will be replaced at signature time.    | Code | Description | Example | | ------------------------- | ------------ | ------------ | | {sUserFirstname} | The first name of the contact | John | | {sUserLastname} | The last name of the contact | Doe | | {sUserJobtitle} | The job title | Sales Representative | | {sCompany} | Company name | eZmax Solutions Inc. | | {sEmailAddress} | The email address | email@example.com | | {sPhoneE164} | A phone number in E.164 Format | +15149901516 | | {sPhoneE164Cell} | A phone number in E.164 Format | +15149901516 | | [optional] [default to undefined]
**iEzsignformfieldgroupFilledmin** | **number** | The minimum number of Ezsignformfield that must be filled in the Ezsignformfieldgroup | [default to undefined]
**iEzsignformfieldgroupFilledmax** | **number** | The maximum number of Ezsignformfield that must be filled in the Ezsignformfieldgroup | [default to undefined]
**bEzsignformfieldgroupReadonly** | **boolean** | Whether the Ezsignformfieldgroup is read only or not. | [default to undefined]
**iEzsignformfieldgroupMaxlength** | **number** | The maximum length for the value in the Ezsignformfieldgroup  This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea** | [optional] [default to undefined]
**bEzsignformfieldgroupEncrypted** | **boolean** | Whether the Ezsignformfieldgroup is encrypted in the database or not. Encrypted values are not displayed on the Ezsigndocument. This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea** | [optional] [default to undefined]
**sEzsignformfieldgroupRegexp** | **string** | A regular expression to indicate what values are acceptable for the Ezsignformfieldgroup.  This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea** | [optional] [default to undefined]
**sEzsignformfieldgroupTextvalidationcustommessage** | **string** | Description of validation rule. Show by signatory. | [optional] [default to undefined]
**tEzsignformfieldgroupTooltip** | **string** | A tooltip that will be presented to Ezsignsigner about the Ezsignformfieldgroup | [optional] [default to undefined]
**eEzsignformfieldgroupTooltipposition** | [**FieldEEzsignformfieldgroupTooltipposition**](FieldEEzsignformfieldgroupTooltipposition.md) |  | [optional] [default to undefined]
**eEzsignformfieldgroupTextvalidation** | [**EnumTextvalidation**](EnumTextvalidation.md) |  | [optional] [default to undefined]
**a_objEzsignformfieldgroupsigner** | [**Array&lt;EzsignformfieldgroupsignerRequestCompound&gt;**](EzsignformfieldgroupsignerRequestCompound.md) |  | [default to undefined]
**a_objDropdownElement** | [**Array&lt;CustomDropdownElementRequestCompound&gt;**](CustomDropdownElementRequestCompound.md) |  | [optional] [default to undefined]
**a_objEzsignformfield** | [**Array&lt;EzsignformfieldRequestCompound&gt;**](EzsignformfieldRequestCompound.md) |  | [default to undefined]
**objCreateezsignelementspositionedbyword** | [**CustomCreateEzsignelementsPositionedByWordRequest**](CustomCreateEzsignelementsPositionedByWordRequest.md) |  | [default to undefined]

## Example

```typescript
import { CustomEzsignformfieldgroupCreateEzsignelementsPositionedByWordRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsignformfieldgroupCreateEzsignelementsPositionedByWordRequest = {
    pkiEzsignformfieldgroupID,
    fkiEzsigndocumentID,
    eEzsignformfieldgroupType,
    eEzsignformfieldgroupSignerrequirement,
    sEzsignformfieldgroupLabel,
    iEzsignformfieldgroupStep,
    sEzsignformfieldgroupDefaultvalue,
    iEzsignformfieldgroupFilledmin,
    iEzsignformfieldgroupFilledmax,
    bEzsignformfieldgroupReadonly,
    iEzsignformfieldgroupMaxlength,
    bEzsignformfieldgroupEncrypted,
    sEzsignformfieldgroupRegexp,
    sEzsignformfieldgroupTextvalidationcustommessage,
    tEzsignformfieldgroupTooltip,
    eEzsignformfieldgroupTooltipposition,
    eEzsignformfieldgroupTextvalidation,
    a_objEzsignformfieldgroupsigner,
    a_objDropdownElement,
    a_objEzsignformfield,
    objCreateezsignelementspositionedbyword,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
