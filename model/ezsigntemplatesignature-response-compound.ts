/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureResponse } from './ezsigntemplatesignature-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureResponseCompoundAllOf } from './ezsigntemplatesignature-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignaturecustomdateResponseCompound } from './ezsigntemplatesignaturecustomdate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureAttachmentnamesource } from './field-eezsigntemplatesignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureFont } from './field-eezsigntemplatesignature-font';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureTooltipposition } from './field-eezsigntemplatesignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureType } from './field-eezsigntemplatesignature-type';

/**
 * @type EzsigntemplatesignatureResponseCompound
 * A Ezsigntemplatesignature Object
 * @export
 */
export type EzsigntemplatesignatureResponseCompound = EzsigntemplatesignatureResponse & EzsigntemplatesignatureResponseCompoundAllOf;



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatesignatureResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureResponseCompound
 */
export class DataObjectEzsigntemplatesignatureResponseCompound {
    pkiEzsigntemplatesignatureID:number = 0
    fkiEzsigntemplatedocumentID:number = 0
    fkiEzsigntemplatesignerID:number = 0
    fkiEzsigntemplatesignerIDValidation?:number = undefined
    iEzsigntemplatedocumentpagePagenumber:number = 0
    iEzsigntemplatesignatureX:number = 0
    iEzsigntemplatesignatureY:number = 0
    iEzsigntemplatesignatureStep:number = 0
    eEzsigntemplatesignatureType:FieldEEzsigntemplatesignatureType = 'Acknowledgement'
    tEzsigntemplatesignatureTooltip?:string = undefined
    eEzsigntemplatesignatureTooltipposition?:FieldEEzsigntemplatesignatureTooltipposition = undefined
    eEzsigntemplatesignatureFont?:FieldEEzsigntemplatesignatureFont = undefined
    iEzsigntemplatesignatureValidationstep?:number = undefined
    sEzsigntemplatesignatureAttachmentdescription?:string = undefined
    eEzsigntemplatesignatureAttachmentnamesource?:FieldEEzsigntemplatesignatureAttachmentnamesource = undefined
    bEzsigntemplatesignatureRequired?:boolean = undefined
    bEzsigntemplatesignatureCustomdate?:boolean = undefined
    a_objEzsigntemplatesignaturecustomdate?:Array<EzsigntemplatesignaturecustomdateResponseCompound> = undefined
}

/**
 * @export 
 * A EzsigntemplatesignatureResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplatesignatureResponseCompound
 */
export class ValidationObjectEzsigntemplatesignatureResponseCompound {
   pkiEzsigntemplatesignatureID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatesignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatesignerIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsigntemplatedocumentpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   iEzsigntemplatesignatureX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatesignatureY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatesignatureStep = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   eEzsigntemplatesignatureType = {
      type: 'enum',
      allowableValues: ['Acknowledgement','City','Handwritten','Initials','Name','Attachments'],
      required: true
   }
   tEzsigntemplatesignatureTooltip = {
      type: 'string',
      required: false
   }
   eEzsigntemplatesignatureTooltipposition = {
      type: 'enum',
      allowableValues: ['TopLeft','TopCenter','TopRight','MiddleLeft','MiddleRight','BottomLeft','BottomCenter','BottomRight'],
      required: false
   }
   eEzsigntemplatesignatureFont = {
      type: 'enum',
      allowableValues: ['Normal','Cursive'],
      required: false
   }
   iEzsigntemplatesignatureValidationstep = {
      type: 'integer',
      required: false
   }
   sEzsigntemplatesignatureAttachmentdescription = {
      type: 'string',
      required: false
   }
   eEzsigntemplatesignatureAttachmentnamesource = {
      type: 'enum',
      allowableValues: ['Description','Customer','DescriptionCustomer'],
      required: false
   }
   bEzsigntemplatesignatureRequired = {
      type: 'boolean',
      required: false
   }
   bEzsigntemplatesignatureCustomdate = {
      type: 'boolean',
      required: false
   }
   a_objEzsigntemplatesignaturecustomdate = {
      type: 'array',
      required: false
   }
} 


