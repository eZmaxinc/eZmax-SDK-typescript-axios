/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CustomContactNameResponse } from './custom-contact-name-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CustomCreditcardtransactionResponse } from './custom-creditcardtransaction-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CustomTimezoneWithCodeResponse } from './custom-timezone-with-code-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignelementdependencyResponseCompound } from './ezsignelementdependency-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignsignatureResponse } from './ezsignsignature-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignsignaturecustomdateResponseCompound } from './ezsignsignaturecustomdate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignsignatureAttachmentnamesource } from './field-eezsignsignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignsignatureConsultationtrigger } from './field-eezsignsignature-consultationtrigger';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignsignatureDependencyrequirement } from './field-eezsignsignature-dependencyrequirement';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignsignatureFont } from './field-eezsignsignature-font';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignsignatureTooltipposition } from './field-eezsignsignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignsignatureType } from './field-eezsignsignature-type';
// May contain unused imports in some cases
// @ts-ignore
import type { SignatureResponseCompound } from './signature-response-compound';

/**
 * @type EzsignsignatureResponseCompound
 * An Ezsignsignature Object and children to create a complete structure
 * @export
 */
/*export type EzsignsignatureResponseCompound = EzsignsignatureResponse;*/
export interface EzsignsignatureResponseCompound {
    /**
     * The unique ID of the Ezsignsignature
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    pkiEzsignsignatureID:number 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    fkiEzsigndocumentID:number 
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    fkiEzsignfoldersignerassociationID:number 
    /**
     * The unique ID of the Ezsignsigningreason
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    fkiEzsignsigningreasonID?:number 
    /**
     * The unique ID of the Font
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    fkiFontID?:number 
    /**
     * The description of the Ezsignsigningreason in the language of the requester
     * @type {string}
     * @memberof EzsignsignatureResponseCompound
     */
    sEzsignsigningreasonDescriptionX?:string 
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    iEzsignpagePagenumber:number 
    /**
     * The X coordinate (Horizontal) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    iEzsignsignatureX:number 
    /**
     * The Y coordinate (Vertical) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    iEzsignsignatureY:number 
    /**
     * The height of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have an height of 2 inches, you would use \"200\" for the iEzsignsignatureHeight.
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    iEzsignsignatureHeight?:number 
    /**
     * The width of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have a width of 2 inches, you would use \"200\" for the iEzsignsignatureWidth.
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    iEzsignsignatureWidth?:number 
    /**
     * The step when the Ezsignsigner will be invited to sign
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    iEzsignsignatureStep:number 
    /**
     * The step when the Ezsignsigner will be invited to sign
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    iEzsignsignatureStepadjusted?:number 
    /**
     * 
     * @type {FieldEEzsignsignatureType}
     * @memberof EzsignsignatureResponseCompound
     */
    eEzsignsignatureType:FieldEEzsignsignatureType 
    /**
     * A tooltip that will be presented to Ezsignsigner about the Ezsignsignature
     * @type {string}
     * @memberof EzsignsignatureResponseCompound
     */
    tEzsignsignatureTooltip?:string 
    /**
     * 
     * @type {FieldEEzsignsignatureTooltipposition}
     * @memberof EzsignsignatureResponseCompound
     */
    eEzsignsignatureTooltipposition?:FieldEEzsignsignatureTooltipposition 
    /**
     * 
     * @type {FieldEEzsignsignatureFont}
     * @memberof EzsignsignatureResponseCompound
     */
    eEzsignsignatureFont?:FieldEEzsignsignatureFont 
    /**
     * The step when the Ezsignsigner will be invited to validate the Ezsignsignature of eEzsignsignatureType Attachments
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    iEzsignsignatureValidationstep?:number 
    /**
     * The description attached to the attachment name added in Ezsignsignature of eEzsignsignatureType Attachments
     * @type {string}
     * @memberof EzsignsignatureResponseCompound
     */
    sEzsignsignatureAttachmentdescription?:string 
    /**
     * 
     * @type {FieldEEzsignsignatureAttachmentnamesource}
     * @memberof EzsignsignatureResponseCompound
     */
    eEzsignsignatureAttachmentnamesource?:FieldEEzsignsignatureAttachmentnamesource 
    /**
     * 
     * @type {FieldEEzsignsignatureConsultationtrigger}
     * @memberof EzsignsignatureResponseCompound
     */
    eEzsignsignatureConsultationtrigger?:FieldEEzsignsignatureConsultationtrigger 
    /**
     * Whether the Ezsignsignature must be handwritten or not when eEzsignsignatureType = Signature.
     * @type {boolean}
     * @memberof EzsignsignatureResponseCompound
     */
    bEzsignsignatureHandwritten?:boolean 
    /**
     * Whether the Ezsignsignature must include a reason or not when eEzsignsignatureType = Signature.
     * @type {boolean}
     * @memberof EzsignsignatureResponseCompound
     */
    bEzsignsignatureReason?:boolean 
    /**
     * Whether the Ezsignsignature is required or not. This field is relevant only with Ezsignsignature with eEzsignsignatureType = Attachments, Text or Textarea.
     * @type {boolean}
     * @memberof EzsignsignatureResponseCompound
     */
    bEzsignsignatureRequired?:boolean 
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    fkiEzsignfoldersignerassociationIDValidation?:number 
    /**
     * The date the Ezsignsignature was signed
     * @type {string}
     * @memberof EzsignsignatureResponseCompound
     */
    dtEzsignsignatureDate?:string 
    /**
     * The count of Ezsignsignatureattachment
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    iEzsignsignatureattachmentCount?:number 
    /**
     * The value entered while signing Ezsignsignature of eEzsignsignatureType **City**, **FieldText** and **FieldTextarea**
     * @type {string}
     * @memberof EzsignsignatureResponseCompound
     */
    sEzsignsignatureDescription?:string 
    /**
     * The maximum length for the value in the Ezsignsignature  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea**
     * @type {number}
     * @memberof EzsignsignatureResponseCompound
     */
    iEzsignsignatureMaxlength?:number 
    /**
     * 
     * @type {EnumTextvalidation}
     * @memberof EzsignsignatureResponseCompound
     */
    eEzsignsignatureTextvalidation?:EnumTextvalidation 
    /**
     * Description of validation rule. Show by signatory.
     * @type {string}
     * @memberof EzsignsignatureResponseCompound
     */
    sEzsignsignatureTextvalidationcustommessage?:string 
    /**
     * 
     * @type {FieldEEzsignsignatureDependencyrequirement}
     * @memberof EzsignsignatureResponseCompound
     */
    eEzsignsignatureDependencyrequirement?:FieldEEzsignsignatureDependencyrequirement 
    /**
     * The default value for the Ezsignsignature  You can use the codes below and they will be replaced at signature time.    | Code | Description | Example | | ------------------------- | ------------ | ------------ | | {sUserFirstname} | The first name of the contact | John | | {sUserLastname} | The last name of the contact | Doe | | {sUserJobtitle} | The job title | Sales Representative | | {sCompany} | Company name | eZmax Solutions Inc. | | {sEmailAddress} | The email address | email@example.com | | {sPhoneE164} | A phone number in E.164 Format | +15149901516 | | {sPhoneE164Cell} | A phone number in E.164 Format | +15149901516 |
     * @type {string}
     * @memberof EzsignsignatureResponseCompound
     */
    sEzsignsignatureDefaultvalue?:string 
    /**
     * A regular expression to indicate what values are acceptable for the Ezsignsignature.  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea** and eEzsignsignatureTextvalidation is **Custom**
     * @type {string}
     * @memberof EzsignsignatureResponseCompound
     */
    sEzsignsignatureRegexp?:string 
    /**
     * 
     * @type {CustomContactNameResponse}
     * @memberof EzsignsignatureResponseCompound
     */
    objContactName:CustomContactNameResponse 
    /**
     * 
     * @type {CustomContactNameResponse}
     * @memberof EzsignsignatureResponseCompound
     */
    objContactNameDelegation?:CustomContactNameResponse 
    /**
     * 
     * @type {SignatureResponseCompound}
     * @memberof EzsignsignatureResponseCompound
     */
    objSignature?:SignatureResponseCompound 
    /**
     * The date the Ezsignsignature was signed in folder\'s timezone
     * @type {string}
     * @memberof EzsignsignatureResponseCompound
     */
    dtEzsignsignatureDateInFolderTimezone?:string 
    /**
     * The Description of the Ezsignsignergroup in the language of the requester
     * @type {string}
     * @memberof EzsignsignatureResponseCompound
     */
    sEzsignsignergroupDescriptionX?:string 
    /**
     * Whether the Ezsignsignature has a custom date format or not. (Only possible when eEzsignsignatureType is **Name** or **Handwritten**)
     * @type {boolean}
     * @memberof EzsignsignatureResponseCompound
     */
    bEzsignsignatureCustomdate?:boolean 
    /**
     * An array of custom date blocks that will be filled at the time of signature.  Can only be used if bEzsignsignatureCustomdate is true.  Use an empty array if you don\'t want to have a date at all.
     * @type {Array<EzsignsignaturecustomdateResponseCompound>}
     * @memberof EzsignsignatureResponseCompound
     */
    a_objEzsignsignaturecustomdate?:Array<EzsignsignaturecustomdateResponseCompound> 
    /**
     * 
     * @type {CustomCreditcardtransactionResponse}
     * @memberof EzsignsignatureResponseCompound
     */
    objCreditcardtransaction?:CustomCreditcardtransactionResponse 
    /**
     * 
     * @type {Array<EzsignelementdependencyResponseCompound>}
     * @memberof EzsignsignatureResponseCompound
     */
    a_objEzsignelementdependency?:Array<EzsignelementdependencyResponseCompound> 
    /**
     * 
     * @type {CustomTimezoneWithCodeResponse}
     * @memberof EzsignsignatureResponseCompound
     */
    objTimezone?:CustomTimezoneWithCodeResponse 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomContactNameResponse } from './'
// @ts-ignore
import { DataObjectCustomContactNameResponse } from './'
// @ts-ignore
import { DataObjectSignatureResponseCompound } from './'
// @ts-ignore
import { DataObjectCustomCreditcardtransactionResponse } from './'
// @ts-ignore
import { DataObjectCustomTimezoneWithCodeResponse } from './'
// @ts-ignore
import { ValidationObjectCustomContactNameResponse } from './'
// @ts-ignore
import { ValidationObjectCustomContactNameResponse } from './'
// @ts-ignore
import { ValidationObjectSignatureResponseCompound } from './'
// @ts-ignore
import { ValidationObjectCustomCreditcardtransactionResponse } from './'
// @ts-ignore
import { ValidationObjectCustomTimezoneWithCodeResponse } from './'

/**
 * @export 
 * A EzsignsignatureResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureResponseCompound
 */
export class DataObjectEzsignsignatureResponseCompound {
    pkiEzsignsignatureID:number = 0
    fkiEzsigndocumentID:number = 0
    fkiEzsignfoldersignerassociationID:number = 0
    fkiEzsignsigningreasonID?:number = undefined
    fkiFontID?:number = undefined
    sEzsignsigningreasonDescriptionX?:string = undefined
    iEzsignpagePagenumber:number = 0
    iEzsignsignatureX:number = 0
    iEzsignsignatureY:number = 0
    iEzsignsignatureHeight?:number = undefined
    iEzsignsignatureWidth?:number = undefined
    iEzsignsignatureStep:number = 0
    iEzsignsignatureStepadjusted?:number = undefined
    eEzsignsignatureType:FieldEEzsignsignatureType = 'Acknowledgement'
    tEzsignsignatureTooltip?:string = undefined
    eEzsignsignatureTooltipposition?:FieldEEzsignsignatureTooltipposition = undefined
    eEzsignsignatureFont?:FieldEEzsignsignatureFont = undefined
    iEzsignsignatureValidationstep?:number = undefined
    sEzsignsignatureAttachmentdescription?:string = undefined
    eEzsignsignatureAttachmentnamesource?:FieldEEzsignsignatureAttachmentnamesource = undefined
    eEzsignsignatureConsultationtrigger?:FieldEEzsignsignatureConsultationtrigger = undefined
    bEzsignsignatureHandwritten?:boolean = undefined
    bEzsignsignatureReason?:boolean = undefined
    bEzsignsignatureRequired?:boolean = undefined
    fkiEzsignfoldersignerassociationIDValidation?:number = undefined
    dtEzsignsignatureDate?:string = undefined
    iEzsignsignatureattachmentCount?:number = undefined
    sEzsignsignatureDescription?:string = undefined
    iEzsignsignatureMaxlength?:number = undefined
    eEzsignsignatureTextvalidation?:EnumTextvalidation = undefined
    sEzsignsignatureTextvalidationcustommessage?:string = undefined
    eEzsignsignatureDependencyrequirement?:FieldEEzsignsignatureDependencyrequirement = undefined
    sEzsignsignatureDefaultvalue?:string = undefined
    sEzsignsignatureRegexp?:string = undefined
    objContactName:CustomContactNameResponse = new DataObjectCustomContactNameResponse()
    objContactNameDelegation?:CustomContactNameResponse = undefined
    objSignature?:SignatureResponseCompound = undefined
    dtEzsignsignatureDateInFolderTimezone?:string = undefined
    sEzsignsignergroupDescriptionX?:string = undefined
    bEzsignsignatureCustomdate?:boolean = undefined
    a_objEzsignsignaturecustomdate?:Array<EzsignsignaturecustomdateResponseCompound> = undefined
    objCreditcardtransaction?:CustomCreditcardtransactionResponse = undefined
    a_objEzsignelementdependency?:Array<EzsignelementdependencyResponseCompound> = undefined
    objTimezone?:CustomTimezoneWithCodeResponse = undefined
}

/**
 * @export 
 * A EzsignsignatureResponseCompound Validation Object
 * @class ValidationObjectEzsignsignatureResponseCompound
 */
export class ValidationObjectEzsignsignatureResponseCompound {
   pkiEzsignsignatureID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignsigningreasonID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   fkiFontID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsignsigningreasonDescriptionX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
   iEzsignpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   iEzsignsignatureX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignsignatureY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignsignatureHeight = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignsignatureWidth = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignsignatureStep = {
      type: 'integer',
      required: true
   }
   iEzsignsignatureStepadjusted = {
      type: 'integer',
      required: false
   }
   eEzsignsignatureType = {
      type: 'enum',
      allowableValues: ['Acknowledgement','City','Handwritten','Initials','Name','NameReason','Attachments','AttachmentsConfirmation','FieldText','FieldTextarea','Consultation','Signature'],
      required: true
   }
   tEzsignsignatureTooltip = {
      type: 'string',
      required: false
   }
   eEzsignsignatureTooltipposition = {
      type: 'enum',
      allowableValues: ['TopLeft','TopCenter','TopRight','MiddleLeft','MiddleRight','BottomLeft','BottomCenter','BottomRight'],
      required: false
   }
   eEzsignsignatureFont = {
      type: 'enum',
      allowableValues: ['Normal','Cursive'],
      required: false
   }
   iEzsignsignatureValidationstep = {
      type: 'integer',
      required: false
   }
   sEzsignsignatureAttachmentdescription = {
      type: 'string',
      required: false
   }
   eEzsignsignatureAttachmentnamesource = {
      type: 'enum',
      allowableValues: ['Description','Customer','DescriptionCustomer'],
      required: false
   }
   eEzsignsignatureConsultationtrigger = {
      type: 'enum',
      allowableValues: ['Automatic','Manual'],
      required: false
   }
   bEzsignsignatureHandwritten = {
      type: 'boolean',
      required: false
   }
   bEzsignsignatureReason = {
      type: 'boolean',
      required: false
   }
   bEzsignsignatureRequired = {
      type: 'boolean',
      required: false
   }
   fkiEzsignfoldersignerassociationIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   dtEzsignsignatureDate = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: false
   }
   iEzsignsignatureattachmentCount = {
      type: 'integer',
      required: false
   }
   sEzsignsignatureDescription = {
      type: 'string',
      required: false
   }
   iEzsignsignatureMaxlength = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   eEzsignsignatureTextvalidation = {
      type: 'enum',
      allowableValues: ['None','Date (YYYY-MM-DD)','Date (MM/DD/YYYY)','Date (MM/DD/YY)','Date (DD/MM/YYYY)','Date (DD/MM/YY)','Email','Letters','Numbers','Zip','Zip+4','PostalCode','Custom'],
      required: false
   }
   sEzsignsignatureTextvalidationcustommessage = {
      type: 'string',
      minLength: 0,
      maxLength: 50,
      required: false
   }
   eEzsignsignatureDependencyrequirement = {
      type: 'enum',
      allowableValues: ['AllOf','AnyOf'],
      required: false
   }
   sEzsignsignatureDefaultvalue = {
      type: 'string',
      required: false
   }
   sEzsignsignatureRegexp = {
      type: 'string',
      pattern: /^\^.*\$$|^$/,
      required: false
   }
   objContactName = new ValidationObjectCustomContactNameResponse()
   objContactNameDelegation = new ValidationObjectCustomContactNameResponse()
   objSignature = new ValidationObjectSignatureResponseCompound()
   dtEzsignsignatureDateInFolderTimezone = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: false
   }
   sEzsignsignergroupDescriptionX = {
      type: 'string',
      required: false
   }
   bEzsignsignatureCustomdate = {
      type: 'boolean',
      required: false
   }
   a_objEzsignsignaturecustomdate = {
      type: 'array',
      required: false
   }
   objCreditcardtransaction = new ValidationObjectCustomCreditcardtransactionResponse()
   a_objEzsignelementdependency = {
      type: 'array',
      required: false
   }
   objTimezone = new ValidationObjectCustomTimezoneWithCodeResponse()
} 


