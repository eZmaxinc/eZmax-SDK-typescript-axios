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
import type { EzsigntemplatedocumentpagerecognitionRequest } from './ezsigntemplatedocumentpagerecognition-request';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatedocumentpagerecognitionOperator } from './field-eezsigntemplatedocumentpagerecognition-operator';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatedocumentpagerecognitionSection } from './field-eezsigntemplatedocumentpagerecognition-section';

/**
 * @type EzsigntemplatedocumentpagerecognitionRequestCompound
 * A Ezsigntemplatedocumentpagerecognition Object and children
 * @export
 */
/*export type EzsigntemplatedocumentpagerecognitionRequestCompound = EzsigntemplatedocumentpagerecognitionRequest;*/
export interface EzsigntemplatedocumentpagerecognitionRequestCompound {
    /**
     * The unique ID of the Ezsigntemplatedocumentpagerecognition
     * @type {number}
     * @memberof EzsigntemplatedocumentpagerecognitionRequestCompound
     */
    pkiEzsigntemplatedocumentpagerecognitionID?:number 
    /**
     * The unique ID of the Ezsigntemplatedocumentpage
     * @type {number}
     * @memberof EzsigntemplatedocumentpagerecognitionRequestCompound
     */
    fkiEzsigntemplatedocumentpageID:number 
    /**
     * 
     * @type {FieldEEzsigntemplatedocumentpagerecognitionOperator}
     * @memberof EzsigntemplatedocumentpagerecognitionRequestCompound
     */
    eEzsigntemplatedocumentpagerecognitionOperator:FieldEEzsigntemplatedocumentpagerecognitionOperator 
    /**
     * 
     * @type {FieldEEzsigntemplatedocumentpagerecognitionSection}
     * @memberof EzsigntemplatedocumentpagerecognitionRequestCompound
     */
    eEzsigntemplatedocumentpagerecognitionSection:FieldEEzsigntemplatedocumentpagerecognitionSection 
    /**
     * The similarpercentage of the Ezsigntemplatedocumentpagerecognition
     * @type {number}
     * @memberof EzsigntemplatedocumentpagerecognitionRequestCompound
     */
    iEzsigntemplatedocumentpagerecognitionSimilarpercentage?:number 
    /**
     * The x of the Ezsigntemplatedocumentpagerecognition
     * @type {number}
     * @memberof EzsigntemplatedocumentpagerecognitionRequestCompound
     */
    iEzsigntemplatedocumentpagerecognitionX?:number 
    /**
     * The y of the Ezsigntemplatedocumentpagerecognition
     * @type {number}
     * @memberof EzsigntemplatedocumentpagerecognitionRequestCompound
     */
    iEzsigntemplatedocumentpagerecognitionY?:number 
    /**
     * The width of the Ezsigntemplatedocumentpagerecognition
     * @type {number}
     * @memberof EzsigntemplatedocumentpagerecognitionRequestCompound
     */
    iEzsigntemplatedocumentpagerecognitionWidth?:number 
    /**
     * The height of the Ezsigntemplatedocumentpagerecognition
     * @type {number}
     * @memberof EzsigntemplatedocumentpagerecognitionRequestCompound
     */
    iEzsigntemplatedocumentpagerecognitionHeight?:number 
    /**
     * The text of the Ezsigntemplatedocumentpagerecognition
     * @type {string}
     * @memberof EzsigntemplatedocumentpagerecognitionRequestCompound
     */
    tEzsigntemplatedocumentpagerecognitionText:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentpagerecognitionRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentpagerecognitionRequestCompound
 */
export class DataObjectEzsigntemplatedocumentpagerecognitionRequestCompound {
    pkiEzsigntemplatedocumentpagerecognitionID?:number = undefined
    fkiEzsigntemplatedocumentpageID:number = 0
    eEzsigntemplatedocumentpagerecognitionOperator:FieldEEzsigntemplatedocumentpagerecognitionOperator = 'eq'
    eEzsigntemplatedocumentpagerecognitionSection:FieldEEzsigntemplatedocumentpagerecognitionSection = 'FirstLine'
    iEzsigntemplatedocumentpagerecognitionSimilarpercentage?:number = undefined
    iEzsigntemplatedocumentpagerecognitionX?:number = undefined
    iEzsigntemplatedocumentpagerecognitionY?:number = undefined
    iEzsigntemplatedocumentpagerecognitionWidth?:number = undefined
    iEzsigntemplatedocumentpagerecognitionHeight?:number = undefined
    tEzsigntemplatedocumentpagerecognitionText:string = ''
}

/**
 * @export 
 * A EzsigntemplatedocumentpagerecognitionRequestCompound Validation Object
 * @class ValidationObjectEzsigntemplatedocumentpagerecognitionRequestCompound
 */
export class ValidationObjectEzsigntemplatedocumentpagerecognitionRequestCompound {
   pkiEzsigntemplatedocumentpagerecognitionID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiEzsigntemplatedocumentpageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   eEzsigntemplatedocumentpagerecognitionOperator = {
      type: 'enum',
      allowableValues: ['eq','in','similar'],
      required: true
   }
   eEzsigntemplatedocumentpagerecognitionSection = {
      type: 'enum',
      allowableValues: ['FirstLine','LastLine','Page','Region'],
      required: true
   }
   iEzsigntemplatedocumentpagerecognitionSimilarpercentage = {
      type: 'integer',
      minimum: 60,
      maximum: 100,
      required: false
   }
   iEzsigntemplatedocumentpagerecognitionX = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   iEzsigntemplatedocumentpagerecognitionY = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   iEzsigntemplatedocumentpagerecognitionWidth = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   iEzsigntemplatedocumentpagerecognitionHeight = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   tEzsigntemplatedocumentpagerecognitionText = {
      type: 'string',
      pattern: /^[.\D\d]{0,65535}$/,
      required: true
   }
} 


