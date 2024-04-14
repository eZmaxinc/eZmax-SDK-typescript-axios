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
import { CustomContactNameResponse } from './custom-contact-name-response';
// May contain unused imports in some cases
// @ts-ignore
import { EnumTextvalidation } from './enum-textvalidation';
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
 * An Ezsignsignature Object
 * @export
 * @interface EzsignsignatureResponse
 */
export interface EzsignsignatureResponse {
    /**
     * The unique ID of the Ezsignsignature
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'pkiEzsignsignatureID': number;*/
    'pkiEzsignsignatureID': number;
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'fkiEzsigndocumentID': number;*/
    'fkiEzsigndocumentID': number;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'fkiEzsignfoldersignerassociationID': number;*/
    'fkiEzsignfoldersignerassociationID': number;
    /**
     * The unique ID of the Ezsignsigningreason
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'fkiEzsignsigningreasonID'?: number;*/
    'fkiEzsignsigningreasonID'?: number;
    /**
     * The description of the Ezsignsigningreason in the language of the requester
     * @type {string}
     * @memberof EzsignsignatureResponse
     */
    /*'sEzsignsigningreasonDescriptionX'?: string;*/
    'sEzsignsigningreasonDescriptionX'?: string;
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'iEzsignpagePagenumber': number;*/
    'iEzsignpagePagenumber': number;
    /**
     * The X coordinate (Horizontal) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'iEzsignsignatureX': number;*/
    'iEzsignsignatureX': number;
    /**
     * The Y coordinate (Vertical) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'iEzsignsignatureY': number;*/
    'iEzsignsignatureY': number;
    /**
     * The height of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have an height of 2 inches, you would use \"200\" for the iEzsignsignatureHeight.
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'iEzsignsignatureHeight'?: number;*/
    'iEzsignsignatureHeight'?: number;
    /**
     * The width of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have a width of 2 inches, you would use \"200\" for the iEzsignsignatureWidth.
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'iEzsignsignatureWidth'?: number;*/
    'iEzsignsignatureWidth'?: number;
    /**
     * The step when the Ezsignsigner will be invited to sign
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'iEzsignsignatureStep': number;*/
    'iEzsignsignatureStep': number;
    /**
     * The step when the Ezsignsigner will be invited to sign
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'iEzsignsignatureStepadjusted'?: number;*/
    'iEzsignsignatureStepadjusted'?: number;
    /**
     * 
     * @type {FieldEEzsignsignatureType}
     * @memberof EzsignsignatureResponse
     */
    /*'eEzsignsignatureType': FieldEEzsignsignatureType;*/
    'eEzsignsignatureType': FieldEEzsignsignatureType;
    /**
     * A tooltip that will be presented to Ezsignsigner about the Ezsignsignature
     * @type {string}
     * @memberof EzsignsignatureResponse
     */
    /*'tEzsignsignatureTooltip'?: string;*/
    'tEzsignsignatureTooltip'?: string;
    /**
     * 
     * @type {FieldEEzsignsignatureTooltipposition}
     * @memberof EzsignsignatureResponse
     */
    /*'eEzsignsignatureTooltipposition'?: FieldEEzsignsignatureTooltipposition;*/
    'eEzsignsignatureTooltipposition'?: FieldEEzsignsignatureTooltipposition;
    /**
     * 
     * @type {FieldEEzsignsignatureFont}
     * @memberof EzsignsignatureResponse
     */
    /*'eEzsignsignatureFont'?: FieldEEzsignsignatureFont;*/
    'eEzsignsignatureFont'?: FieldEEzsignsignatureFont;
    /**
     * The step when the Ezsignsigner will be invited to validate the Ezsignsignature of eEzsignsignatureType Attachments
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'iEzsignsignatureValidationstep'?: number;*/
    'iEzsignsignatureValidationstep'?: number;
    /**
     * The description attached to the attachment name added in Ezsignsignature of eEzsignsignatureType Attachments
     * @type {string}
     * @memberof EzsignsignatureResponse
     */
    /*'sEzsignsignatureAttachmentdescription'?: string;*/
    'sEzsignsignatureAttachmentdescription'?: string;
    /**
     * 
     * @type {FieldEEzsignsignatureAttachmentnamesource}
     * @memberof EzsignsignatureResponse
     */
    /*'eEzsignsignatureAttachmentnamesource'?: FieldEEzsignsignatureAttachmentnamesource;*/
    'eEzsignsignatureAttachmentnamesource'?: FieldEEzsignsignatureAttachmentnamesource;
    /**
     * Whether the Ezsignsignature is required or not. This field is relevant only with Ezsignsignature with eEzsignsignatureType = Attachments.
     * @type {boolean}
     * @memberof EzsignsignatureResponse
     */
    /*'bEzsignsignatureRequired'?: boolean;*/
    'bEzsignsignatureRequired'?: boolean;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'fkiEzsignfoldersignerassociationIDValidation'?: number;*/
    'fkiEzsignfoldersignerassociationIDValidation'?: number;
    /**
     * The date the Ezsignsignature was signed
     * @type {string}
     * @memberof EzsignsignatureResponse
     */
    /*'dtEzsignsignatureDate'?: string;*/
    'dtEzsignsignatureDate'?: string;
    /**
     * The count of Ezsignsignatureattachment
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'iEzsignsignatureattachmentCount'?: number;*/
    'iEzsignsignatureattachmentCount'?: number;
    /**
     * The value entered while signing Ezsignsignature of eEzsignsignatureType **City**, **FieldText** and **FieldTextarea**
     * @type {string}
     * @memberof EzsignsignatureResponse
     */
    /*'sEzsignsignatureDescription'?: string;*/
    'sEzsignsignatureDescription'?: string;
    /**
     * The maximum length for the value in the Ezsignsignature  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea**
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    /*'iEzsignsignatureMaxlength'?: number;*/
    'iEzsignsignatureMaxlength'?: number;
    /**
     * 
     * @type {EnumTextvalidation}
     * @memberof EzsignsignatureResponse
     */
    /*'eEzsignsignatureTextvalidation'?: EnumTextvalidation;*/
    'eEzsignsignatureTextvalidation'?: EnumTextvalidation;
    /**
     * 
     * @type {FieldEEzsignsignatureDependencyrequirement}
     * @memberof EzsignsignatureResponse
     */
    /*'eEzsignsignatureDependencyrequirement'?: FieldEEzsignsignatureDependencyrequirement;*/
    'eEzsignsignatureDependencyrequirement'?: FieldEEzsignsignatureDependencyrequirement;
    /**
     * A regular expression to indicate what values are acceptable for the Ezsignsignature.  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea** and eEzsignsignatureTextvalidation is **Custom**
     * @type {string}
     * @memberof EzsignsignatureResponse
     */
    /*'sEzsignsignatureRegexp'?: string;*/
    'sEzsignsignatureRegexp'?: string;
    /**
     * 
     * @type {CustomContactNameResponse}
     * @memberof EzsignsignatureResponse
     */
    /*'objContactName': CustomContactNameResponse;*/
    'objContactName': CustomContactNameResponse;
    /**
     * 
     * @type {CustomContactNameResponse}
     * @memberof EzsignsignatureResponse
     */
    /*'objContactNameDelegation'?: CustomContactNameResponse;*/
    'objContactNameDelegation'?: CustomContactNameResponse;
    /**
     * 
     * @type {SignatureResponseCompound}
     * @memberof EzsignsignatureResponse
     */
    /*'objSignature'?: SignatureResponseCompound;*/
    'objSignature'?: SignatureResponseCompound;
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
import { ValidationObjectCustomContactNameResponse } from './'
// @ts-ignore
import { ValidationObjectCustomContactNameResponse } from './'
// @ts-ignore
import { ValidationObjectSignatureResponseCompound } from './'

/**
 * @export 
 * A EzsignsignatureResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureResponse
 */
export class DataObjectEzsignsignatureResponse {
   pkiEzsignsignatureID:number = 0
   fkiEzsigndocumentID:number = 0
   fkiEzsignfoldersignerassociationID:number = 0
   fkiEzsignsigningreasonID?:number = undefined
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
}

/**
 * @export 
 * A EzsignsignatureResponse Validation Object
 * @class ValidationObjectEzsignsignatureResponse
 */
export class ValidationObjectEzsignsignatureResponse {
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
   sEzsignsigningreasonDescriptionX = {
      type: 'string',
      pattern: '/^.{0,50}$/',
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
      allowableValues: ['Acknowledgement','City','Handwritten','Initials','Name','NameReason','Attachments','AttachmentsConfirmation','FieldText','FieldTextarea','Consultation'],
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
} 


