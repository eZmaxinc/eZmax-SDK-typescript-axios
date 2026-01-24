# EzsigntemplateformfieldgroupRequestCompound

A Ezsigntemplateformfieldgroup Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplateformfieldgroupID** | **number** | The unique ID of the Ezsigntemplateformfieldgroup | [optional] [default to undefined]
**fkiEzsigntemplatedocumentID** | **number** | The unique ID of the Ezsigntemplatedocument | [default to undefined]
**eEzsigntemplateformfieldgroupType** | [**FieldEEzsigntemplateformfieldgroupType**](FieldEEzsigntemplateformfieldgroupType.md) |  | [default to undefined]
**eEzsigntemplateformfieldgroupSignerrequirement** | [**FieldEEzsigntemplateformfieldgroupSignerrequirement**](FieldEEzsigntemplateformfieldgroupSignerrequirement.md) |  | [optional] [default to undefined]
**sEzsigntemplateformfieldgroupLabel** | **string** | The Label for the Ezsigntemplateformfieldgroup | [default to undefined]
**iEzsigntemplateformfieldgroupStep** | **number** | The step when the Ezsigntemplatesigner will be invited to fill the form fields | [default to undefined]
**sEzsigntemplateformfieldgroupDefaultvalue** | **string** | The default value for the Ezsigntemplateformfieldgroup  You can use the codes below and they will be replaced at signature time.    | Code | Description | Example | | ------------------------- | ------------ | ------------ | | {sUserFirstname} | The first name of the contact | John | | {sUserLastname} | The last name of the contact | Doe | | {sUserJobtitle} | The job title | Sales Representative | | {sEmailAddress} | The email address | email@example.com | | {sPhoneE164} | A phone number in E.164 Format | +15149901516 | | {sPhoneE164Cell} | A phone number in E.164 Format | +15149901516 | | [default to undefined]
**iEzsigntemplateformfieldgroupFilledmin** | **number** | The minimum number of Ezsigntemplateformfield that must be filled in the Ezsigntemplateformfieldgroup | [default to undefined]
**iEzsigntemplateformfieldgroupFilledmax** | **number** | The maximum number of Ezsigntemplateformfield that must be filled in the Ezsigntemplateformfieldgroup | [default to undefined]
**bEzsigntemplateformfieldgroupReadonly** | **boolean** | Whether the Ezsigntemplateformfieldgroup is read only or not. | [default to undefined]
**iEzsigntemplateformfieldgroupMaxlength** | **number** | The maximum length for the value in the Ezsigntemplateformfieldgroup  This can only be set if eEzsigntemplateformfieldgroupType is **Text** or **Textarea** | [optional] [default to undefined]
**bEzsigntemplateformfieldgroupEncrypted** | **boolean** | Whether the Ezsigntemplateformfieldgroup is encrypted in the database or not. Encrypted values are not displayed on the Ezsigndocument. This can only be set if eEzsigntemplateformfieldgroupType is **Text** or **Textarea** | [optional] [default to undefined]
**sEzsigntemplateformfieldgroupRegexp** | **string** | A regular expression to indicate what values are acceptable for the Ezsigntemplateformfieldgroup.  This can only be set if eEzsigntemplateformfieldgroupType is **Text** or **Textarea** | [optional] [default to undefined]
**sEzsigntemplateformfieldgroupTextvalidationcustommessage** | **string** | Description of validation rule. Show by signatory. | [optional] [default to undefined]
**eEzsigntemplateformfieldgroupTextvalidation** | [**EnumTextvalidation**](EnumTextvalidation.md) |  | [optional] [default to undefined]
**tEzsigntemplateformfieldgroupTooltip** | **string** | A tooltip that will be presented to Ezsigntemplatesigner about the Ezsigntemplateformfieldgroup | [optional] [default to undefined]
**eEzsigntemplateformfieldgroupTooltipposition** | [**FieldEEzsigntemplateformfieldgroupTooltipposition**](FieldEEzsigntemplateformfieldgroupTooltipposition.md) |  | [optional] [default to undefined]
**a_objEzsigntemplateformfieldgroupsigner** | [**Array&lt;EzsigntemplateformfieldgroupsignerRequestCompound&gt;**](EzsigntemplateformfieldgroupsignerRequestCompound.md) |  | [default to undefined]
**a_objDropdownElement** | [**Array&lt;CustomDropdownElementRequestCompound&gt;**](CustomDropdownElementRequestCompound.md) |  | [optional] [default to undefined]
**a_objEzsigntemplateformfield** | [**Array&lt;EzsigntemplateformfieldRequestCompound&gt;**](EzsigntemplateformfieldRequestCompound.md) |  | [default to undefined]

## Example

```typescript
import { EzsigntemplateformfieldgroupRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplateformfieldgroupRequestCompound = {
    pkiEzsigntemplateformfieldgroupID,
    fkiEzsigntemplatedocumentID,
    eEzsigntemplateformfieldgroupType,
    eEzsigntemplateformfieldgroupSignerrequirement,
    sEzsigntemplateformfieldgroupLabel,
    iEzsigntemplateformfieldgroupStep,
    sEzsigntemplateformfieldgroupDefaultvalue,
    iEzsigntemplateformfieldgroupFilledmin,
    iEzsigntemplateformfieldgroupFilledmax,
    bEzsigntemplateformfieldgroupReadonly,
    iEzsigntemplateformfieldgroupMaxlength,
    bEzsigntemplateformfieldgroupEncrypted,
    sEzsigntemplateformfieldgroupRegexp,
    sEzsigntemplateformfieldgroupTextvalidationcustommessage,
    eEzsigntemplateformfieldgroupTextvalidation,
    tEzsigntemplateformfieldgroupTooltip,
    eEzsigntemplateformfieldgroupTooltipposition,
    a_objEzsigntemplateformfieldgroupsigner,
    a_objDropdownElement,
    a_objEzsigntemplateformfield,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
