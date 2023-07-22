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
import { EzsigntemplateformfieldRequest } from './ezsigntemplateformfield-request';

/**
 * @type EzsigntemplateformfieldRequestCompound
 * An Ezsigntemplateformfield Object and children to create a complete structure
 * @export
 */
export type EzsigntemplateformfieldRequestCompound = EzsigntemplateformfieldRequest;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateformfieldRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldRequestCompound
 */
export class DataObjectEzsigntemplateformfieldRequestCompound {
    pkiEzsigntemplateformfieldID?:number = undefined
    iEzsigntemplatedocumentpagePagenumber:number = 0
    sEzsigntemplateformfieldLabel:string = ''
    sEzsigntemplateformfieldValue?:string = undefined
    iEzsigntemplateformfieldX:number = 0
    iEzsigntemplateformfieldY:number = 0
    iEzsigntemplateformfieldWidth:number = 0
    iEzsigntemplateformfieldHeight:number = 0
    bEzsigntemplateformfieldSelected?:boolean = undefined
}

/**
 * @export 
 * A EzsigntemplateformfieldRequestCompound Validation Object
 * @class ValidationObjectEzsigntemplateformfieldRequestCompound
 */
export class ValidationObjectEzsigntemplateformfieldRequestCompound {
   pkiEzsigntemplateformfieldID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsigntemplatedocumentpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sEzsigntemplateformfieldLabel = {
      type: 'string',
      required: true
   }
   sEzsigntemplateformfieldValue = {
      type: 'string',
      required: false
   }
   iEzsigntemplateformfieldX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplateformfieldY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplateformfieldWidth = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplateformfieldHeight = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzsigntemplateformfieldSelected = {
      type: 'boolean',
      required: false
   }
} 


