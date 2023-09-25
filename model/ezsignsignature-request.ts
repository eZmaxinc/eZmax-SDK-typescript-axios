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
import { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureAttachmentnamesource } from './field-eezsignsignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureFont } from './field-eezsignsignature-font';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureTooltipposition } from './field-eezsignsignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureType } from './field-eezsignsignature-type';

/**
 * An Ezsignsignature Object
 * @export
 * @interface EzsignsignatureRequest
 */
export interface EzsignsignatureRequest {
    /**
     * The unique ID of the Ezsignsignature
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'pkiEzsignsignatureID'?: number;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'fkiEzsignfoldersignerassociationID': number;
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignpagePagenumber': number;
    /**
     * The X coordinate (Horizontal) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureX': number;
    /**
     * The Y coordinate (Vertical) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureY': number;
    /**
     * The width of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have a width of 2 inches, you would use \"200\" for the iEzsignsignatureWidth.
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureWidth'?: number;
    /**
     * The height of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have an height of 2 inches, you would use \"200\" for the iEzsignsignatureHeight.
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureHeight'?: number;
    /**
     * The step when the Ezsignsigner will be invited to sign
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureStep': number;
    /**
     * 
     * @type {FieldEEzsignsignatureType}
     * @memberof EzsignsignatureRequest
     */
    'eEzsignsignatureType': FieldEEzsignsignatureType;
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'fkiEzsigndocumentID': number;
    /**
     * A tooltip that will be presented to Ezsignsigner about the Ezsignsignature
     * @type {string}
     * @memberof EzsignsignatureRequest
     */
    'tEzsignsignatureTooltip'?: string;
    /**
     * 
     * @type {FieldEEzsignsignatureTooltipposition}
     * @memberof EzsignsignatureRequest
     */
    'eEzsignsignatureTooltipposition'?: FieldEEzsignsignatureTooltipposition;
    /**
     * 
     * @type {FieldEEzsignsignatureFont}
     * @memberof EzsignsignatureRequest
     */
    'eEzsignsignatureFont'?: FieldEEzsignsignatureFont;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'fkiEzsignfoldersignerassociationIDValidation'?: number;
    /**
     * Whether the Ezsignsignature is required or not. This field is relevant only with Ezsignsignature with eEzsignsignatureType = Attachments.
     * @type {boolean}
     * @memberof EzsignsignatureRequest
     */
    'bEzsignsignatureRequired'?: boolean;
    /**
     * 
     * @type {FieldEEzsignsignatureAttachmentnamesource}
     * @memberof EzsignsignatureRequest
     */
    'eEzsignsignatureAttachmentnamesource'?: FieldEEzsignsignatureAttachmentnamesource;
    /**
     * The description attached to the attachment name added in Ezsignsignature of eEzsignsignatureType Attachments
     * @type {string}
     * @memberof EzsignsignatureRequest
     */
    'sEzsignsignatureAttachmentdescription'?: string;
    /**
     * The step when the Ezsignsigner will be invited to validate the Ezsignsignature of eEzsignsignatureType Attachments
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureValidationstep'?: number;
    /**
     * The maximum length for the value in the Ezsignsignature  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea**
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureMaxlength'?: number;
    /**
     * 
     * @type {EnumTextvalidation}
     * @memberof EzsignsignatureRequest
     */
    'eEzsignsignatureTextvalidation'?: EnumTextvalidation;
    /**
     * A regular expression to indicate what values are acceptable for the Ezsignsignature.  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea** and eEzsignsignatureTextvalidation is **Custom**
     * @type {string}
     * @memberof EzsignsignatureRequest
     */
    'sEzsignsignatureRegexp'?: string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignatureRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureRequest
 */
export class DataObjectEzsignsignatureRequest {
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
   bEzsignsignatureRequired?:boolean = undefined
   eEzsignsignatureAttachmentnamesource?:FieldEEzsignsignatureAttachmentnamesource = undefined
   sEzsignsignatureAttachmentdescription?:string = undefined
   iEzsignsignatureValidationstep?:number = undefined
   iEzsignsignatureMaxlength?:number = undefined
   eEzsignsignatureTextvalidation?:EnumTextvalidation = undefined
   sEzsignsignatureRegexp?:string = undefined
}

/**
 * @export 
 * A EzsignsignatureRequest Validation Object
 * @class ValidationObjectEzsignsignatureRequest
 */
export class ValidationObjectEzsignsignatureRequest {
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
      allowableValues: ['Acknowledgement','City','Handwritten','Initials','Name','Attachments','AttachmentsConfirmation','FieldText','FieldTextarea'],
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
   eEzsignsignatureTextvalidation = {
      type: 'enum',
      allowableValues: ['None','Date (YYYY-MM-DD)','Date (MM/DD/YYYY)','Date (MM/DD/YY)','Date (DD/MM/YYYY)','Date (DD/MM/YY)','Email','Letters','Numbers','Zip','Zip+4','PostalCode','Custom'],
      required: false
   }
   sEzsignsignatureRegexp = {
      type: 'string',
      pattern: '/^\^.*\$$|^$/',
      required: false
   }
} 


