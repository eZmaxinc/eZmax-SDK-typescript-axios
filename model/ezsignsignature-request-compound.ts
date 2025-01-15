/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignelementdependencyRequest } from './ezsignelementdependency-request';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignsignatureRequest } from './ezsignsignature-request';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignsignaturecustomdateRequest } from './ezsignsignaturecustomdate-request';
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

/**
 * @type EzsignsignatureRequestCompound
 * An Ezsignsignature Object and children to create a complete structure
 * @export
 */
/*export type EzsignsignatureRequestCompound = EzsignsignatureRequest;*/
export interface EzsignsignatureRequestCompound {
    /**
     * The unique ID of the Ezsignsignature
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    pkiEzsignsignatureID?:number 
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    fkiEzsignfoldersignerassociationID:number 
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    iEzsignpagePagenumber:number 
    /**
     * The X coordinate (Horizontal) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    iEzsignsignatureX:number 
    /**
     * The Y coordinate (Vertical) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    iEzsignsignatureY:number 
    /**
     * The width of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have a width of 2 inches, you would use \"200\" for the iEzsignsignatureWidth.
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    iEzsignsignatureWidth?:number 
    /**
     * The height of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have an height of 2 inches, you would use \"200\" for the iEzsignsignatureHeight.
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    iEzsignsignatureHeight?:number 
    /**
     * The step when the Ezsignsigner will be invited to sign
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    iEzsignsignatureStep:number 
    /**
     * 
     * @type {FieldEEzsignsignatureType}
     * @memberof EzsignsignatureRequestCompound
     */
    eEzsignsignatureType:FieldEEzsignsignatureType 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    fkiEzsigndocumentID:number 
    /**
     * A tooltip that will be presented to Ezsignsigner about the Ezsignsignature
     * @type {string}
     * @memberof EzsignsignatureRequestCompound
     */
    tEzsignsignatureTooltip?:string 
    /**
     * 
     * @type {FieldEEzsignsignatureTooltipposition}
     * @memberof EzsignsignatureRequestCompound
     */
    eEzsignsignatureTooltipposition?:FieldEEzsignsignatureTooltipposition 
    /**
     * 
     * @type {FieldEEzsignsignatureFont}
     * @memberof EzsignsignatureRequestCompound
     */
    eEzsignsignatureFont?:FieldEEzsignsignatureFont 
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    fkiEzsignfoldersignerassociationIDValidation?:number 
    /**
     * Whether the Ezsignsignature must be handwritten or not when eEzsignsignatureType = Signature.
     * @type {boolean}
     * @memberof EzsignsignatureRequestCompound
     */
    bEzsignsignatureHandwritten?:boolean 
    /**
     * Whether the Ezsignsignature must include a reason or not when eEzsignsignatureType = Signature.
     * @type {boolean}
     * @memberof EzsignsignatureRequestCompound
     */
    bEzsignsignatureReason?:boolean 
    /**
     * Whether the Ezsignsignature is required or not. This field is relevant only with Ezsignsignature with eEzsignsignatureType = Attachments, Text or Textarea.
     * @type {boolean}
     * @memberof EzsignsignatureRequestCompound
     */
    bEzsignsignatureRequired?:boolean 
    /**
     * 
     * @type {FieldEEzsignsignatureAttachmentnamesource}
     * @memberof EzsignsignatureRequestCompound
     */
    eEzsignsignatureAttachmentnamesource?:FieldEEzsignsignatureAttachmentnamesource 
    /**
     * The description attached to the attachment name added in Ezsignsignature of eEzsignsignatureType Attachments
     * @type {string}
     * @memberof EzsignsignatureRequestCompound
     */
    sEzsignsignatureAttachmentdescription?:string 
    /**
     * 
     * @type {FieldEEzsignsignatureConsultationtrigger}
     * @memberof EzsignsignatureRequestCompound
     */
    eEzsignsignatureConsultationtrigger?:FieldEEzsignsignatureConsultationtrigger 
    /**
     * The step when the Ezsignsigner will be invited to validate the Ezsignsignature of eEzsignsignatureType Attachments
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    iEzsignsignatureValidationstep?:number 
    /**
     * The maximum length for the value in the Ezsignsignature  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea**
     * @type {number}
     * @memberof EzsignsignatureRequestCompound
     */
    iEzsignsignatureMaxlength?:number 
    /**
     * The default value for the Ezsignsignature  You can use the codes below and they will be replaced at signature time.    | Code | Description | Example | | ------------------------- | ------------ | ------------ | | {sUserFirstname} | The first name of the contact | John | | {sUserLastname} | The last name of the contact | Doe | | {sUserJobtitle} | The job title | Sales Representative | | {sCompany} | Company name | eZmax Solutions Inc. | | {sEmailAddress} | The email address | email@example.com | | {sPhoneE164} | A phone number in E.164 Format | +15149901516 | | {sPhoneE164Cell} | A phone number in E.164 Format | +15149901516 |
     * @type {string}
     * @memberof EzsignsignatureRequestCompound
     */
    sEzsignsignatureDefaultvalue?:string 
    /**
     * 
     * @type {EnumTextvalidation}
     * @memberof EzsignsignatureRequestCompound
     */
    eEzsignsignatureTextvalidation?:EnumTextvalidation 
    /**
     * Description of validation rule. Show by signatory.
     * @type {string}
     * @memberof EzsignsignatureRequestCompound
     */
    sEzsignsignatureTextvalidationcustommessage?:string 
    /**
     * A regular expression to indicate what values are acceptable for the Ezsignsignature.  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea** and eEzsignsignatureTextvalidation is **Custom**
     * @type {string}
     * @memberof EzsignsignatureRequestCompound
     */
    sEzsignsignatureRegexp?:string 
    /**
     * 
     * @type {FieldEEzsignsignatureDependencyrequirement}
     * @memberof EzsignsignatureRequestCompound
     */
    eEzsignsignatureDependencyrequirement?:FieldEEzsignsignatureDependencyrequirement 
    /**
     * Whether the Ezsignsignature has a custom date format or not. (Only possible when eEzsignsignatureType is **Name** or **Handwritten**)
     * @type {boolean}
     * @memberof EzsignsignatureRequestCompound
     */
    bEzsignsignatureCustomdate?:boolean 
    /**
     * An array of custom date blocks that will be filled at the time of signature.  Can only be used if bEzsignsignatureCustomdate is true.  Use an empty array if you don\'t want to have a date at all.
     * @type {Array<EzsignsignaturecustomdateRequestCompound>}
     * @memberof EzsignsignatureRequestCompound
     */
    a_objEzsignsignaturecustomdate?:Array<EzsignsignaturecustomdateRequestCompound> 
    /**
     * 
     * @type {Array<EzsignelementdependencyRequestCompound>}
     * @memberof EzsignsignatureRequestCompound
     */
    a_objEzsignelementdependency?:Array<EzsignelementdependencyRequestCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignatureRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureRequestCompound
 */
export class DataObjectEzsignsignatureRequestCompound {
    pkiEzsignsignatureID?:number = undefined
    fkiEzsignfoldersignerassociationID:number = 0
    iEzsignpagePagenumber:number = 0
    iEzsignsignatureX:number = 0
    iEzsignsignatureY:number = 0
    iEzsignsignatureWidth?:number = undefined
    iEzsignsignatureHeight?:number = undefined
    iEzsignsignatureStep:number = 0
    eEzsignsignatureType:FieldEEzsignsignatureType = 'Acknowledgement'
    fkiEzsigndocumentID:number = 0
    tEzsignsignatureTooltip?:string = undefined
    eEzsignsignatureTooltipposition?:FieldEEzsignsignatureTooltipposition = undefined
    eEzsignsignatureFont?:FieldEEzsignsignatureFont = undefined
    fkiEzsignfoldersignerassociationIDValidation?:number = undefined
    bEzsignsignatureHandwritten?:boolean = undefined
    bEzsignsignatureReason?:boolean = undefined
    bEzsignsignatureRequired?:boolean = undefined
    eEzsignsignatureAttachmentnamesource?:FieldEEzsignsignatureAttachmentnamesource = undefined
    sEzsignsignatureAttachmentdescription?:string = undefined
    eEzsignsignatureConsultationtrigger?:FieldEEzsignsignatureConsultationtrigger = undefined
    iEzsignsignatureValidationstep?:number = undefined
    iEzsignsignatureMaxlength?:number = undefined
    sEzsignsignatureDefaultvalue?:string = undefined
    eEzsignsignatureTextvalidation?:EnumTextvalidation = undefined
    sEzsignsignatureTextvalidationcustommessage?:string = undefined
    sEzsignsignatureRegexp?:string = undefined
    eEzsignsignatureDependencyrequirement?:FieldEEzsignsignatureDependencyrequirement = undefined
    bEzsignsignatureCustomdate?:boolean = undefined
    a_objEzsignsignaturecustomdate?:Array<EzsignsignaturecustomdateRequestCompound> = undefined
    a_objEzsignelementdependency?:Array<EzsignelementdependencyRequestCompound> = undefined
}

/**
 * @export 
 * A EzsignsignatureRequestCompound Validation Object
 * @class ValidationObjectEzsignsignatureRequestCompound
 */
export class ValidationObjectEzsignsignatureRequestCompound {
   pkiEzsignsignatureID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: true
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
   iEzsignsignatureWidth = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignsignatureHeight = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignsignatureStep = {
      type: 'integer',
      required: true
   }
   eEzsignsignatureType = {
      type: 'enum',
      allowableValues: ['Acknowledgement','City','Handwritten','Initials','Name','NameReason','Attachments','AttachmentsConfirmation','FieldText','FieldTextarea','Consultation','Signature'],
      required: true
   }
   fkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
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
   fkiEzsignfoldersignerassociationIDValidation = {
      type: 'integer',
      minimum: 0,
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
   eEzsignsignatureAttachmentnamesource = {
      type: 'enum',
      allowableValues: ['Description','Customer','DescriptionCustomer'],
      required: false
   }
   sEzsignsignatureAttachmentdescription = {
      type: 'string',
      required: false
   }
   eEzsignsignatureConsultationtrigger = {
      type: 'enum',
      allowableValues: ['Automatic','Manual'],
      required: false
   }
   iEzsignsignatureValidationstep = {
      type: 'integer',
      required: false
   }
   iEzsignsignatureMaxlength = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   sEzsignsignatureDefaultvalue = {
      type: 'string',
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
   sEzsignsignatureRegexp = {
      type: 'string',
      pattern: /^\^.*\$$|^$/,
      required: false
   }
   eEzsignsignatureDependencyrequirement = {
      type: 'enum',
      allowableValues: ['AllOf','AnyOf'],
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
   a_objEzsignelementdependency = {
      type: 'array',
      required: false
   }
} 


