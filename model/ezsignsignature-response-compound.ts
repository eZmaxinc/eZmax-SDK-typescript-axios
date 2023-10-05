/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomContactNameResponse } from './custom-contact-name-response';
// May contain unused imports in some cases
// @ts-ignore
import { CustomCreditcardtransactionResponse } from './custom-creditcardtransaction-response';
// May contain unused imports in some cases
// @ts-ignore
import { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignelementdependencyResponseCompound } from './ezsignelementdependency-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureResponse } from './ezsignsignature-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignaturecustomdateResponseCompound } from './ezsignsignaturecustomdate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureAttachmentnamesource } from './field-eezsignsignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureDependencyrequirement } from './field-eezsignsignature-dependencyrequirement';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureFont } from './field-eezsignsignature-font';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureTooltipposition } from './field-eezsignsignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureType } from './field-eezsignsignature-type';
// May contain unused imports in some cases
// @ts-ignore
import { SignatureResponseCompound } from './signature-response-compound';

/**
 * @type EzsignsignatureResponseCompound
 * An Ezsignsignature Object and children to create a complete structure
 * @export
 */
/** export type EzsignsignatureResponseCompound = EzsignsignatureResponse; */
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
     * Whether the Ezsignsignature is required or not. This field is relevant only with Ezsignsignature with eEzsignsignatureType = Attachments.
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
     * 
     * @type {FieldEEzsignsignatureDependencyrequirement}
     * @memberof EzsignsignatureResponseCompound
     */
    eEzsignsignatureDependencyrequirement?:FieldEEzsignsignatureDependencyrequirement 
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
import { ValidationObjectCustomContactNameResponse } from './'
// @ts-ignore
import { ValidationObjectCustomContactNameResponse } from './'
// @ts-ignore
import { ValidationObjectSignatureResponseCompound } from './'
// @ts-ignore
import { ValidationObjectCustomCreditcardtransactionResponse } from './'

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
    iEzsignpagePagenumber:number = 0
    iEzsignsignatureX:number = 0
    iEzsignsignatureY:number = 0
    iEzsignsignatureHeight?:number = undefined
    iEzsignsignatureWidth?:number = undefined
    iEzsignsignatureStep:number = 0
    eEzsignsignatureType:FieldEEzsignsignatureType = 'Acknowledgement'
    tEzsignsignatureTooltip?:string = undefined
    eEzsignsignatureTooltipposition?:FieldEEzsignsignatureTooltipposition = undefined
    eEzsignsignatureFont?:FieldEEzsignsignatureFont = undefined
    iEzsignsignatureValidationstep?:number = undefined
    sEzsignsignatureAttachmentdescription?:string = undefined
    eEzsignsignatureAttachmentnamesource?:FieldEEzsignsignatureAttachmentnamesource = undefined
    bEzsignsignatureRequired?:boolean = undefined
    fkiEzsignfoldersignerassociationIDValidation?:number = undefined
    dtEzsignsignatureDate?:string = undefined
    iEzsignsignatureattachmentCount?:number = undefined
    sEzsignsignatureDescription?:string = undefined
    iEzsignsignatureMaxlength?:number = undefined
    eEzsignsignatureTextvalidation?:EnumTextvalidation = undefined
    eEzsignsignatureDependencyrequirement?:FieldEEzsignsignatureDependencyrequirement = undefined
    sEzsignsignatureRegexp?:string = undefined
    objContactName:CustomContactNameResponse = new DataObjectCustomContactNameResponse()
    objContactNameDelegation?:CustomContactNameResponse = undefined
    objSignature?:SignatureResponseCompound = undefined
    bEzsignsignatureCustomdate?:boolean = undefined
    a_objEzsignsignaturecustomdate?:Array<EzsignsignaturecustomdateResponseCompound> = undefined
    objCreditcardtransaction?:CustomCreditcardtransactionResponse = undefined
    a_objEzsignelementdependency?:Array<EzsignelementdependencyResponseCompound> = undefined
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
   eEzsignsignatureType = {
      type: 'enum',
      allowableValues: ['Acknowledgement','City','Handwritten','Initials','Name','Attachments','AttachmentsConfirmation','FieldText','FieldTextarea'],
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
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/',
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
   eEzsignsignatureDependencyrequirement = {
      type: 'enum',
      allowableValues: ['AllOf','AnyOf'],
      required: false
   }
   sEzsignsignatureRegexp = {
      type: 'string',
      pattern: '/^\^.*\$$|^$/',
      required: false
   }
   objContactName = new ValidationObjectCustomContactNameResponse()
   objContactNameDelegation = new ValidationObjectCustomContactNameResponse()
   objSignature = new ValidationObjectSignatureResponseCompound()
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
} 


