/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldRequest } from './ezsignformfield-request';

/**
 * @type EzsignformfieldRequestCompound
 * An Ezsignformfield Object and children to create a complete structure
 * @export
 */
export type EzsignformfieldRequestCompound = EzsignformfieldRequest;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignformfieldRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignformfieldRequestCompound
 */
export class DataObjectEzsignformfieldRequestCompound {
   pkiEzsignformfieldID?:number = undefined
   iEzsignpagePagenumber:number = 0
   sEzsignformfieldLabel:string = ''
   sEzsignformfieldValue?:string = undefined
   iEzsignformfieldX:number = 0
   iEzsignformfieldY:number = 0
   iEzsignformfieldWidth:number = 0
   iEzsignformfieldHeight:number = 0
   bEzsignformfieldSelected?:boolean = undefined
   sEzsignformfieldEnteredvalue?:string = undefined
}

/**
 * @export 
 * A EzsignformfieldRequestCompound Validation Object
 * @class ValidationObjectEzsignformfieldRequestCompound
 */
export class ValidationObjectEzsignformfieldRequestCompound {
   pkiEzsignformfieldID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sEzsignformfieldLabel = {
      type: 'string',
      required: true
   }
   sEzsignformfieldValue = {
      type: 'string',
      required: false
   }
   iEzsignformfieldX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignformfieldY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignformfieldWidth = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignformfieldHeight = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzsignformfieldSelected = {
      type: 'boolean',
      required: false
   }
   sEzsignformfieldEnteredvalue = {
      type: 'string',
      required: false
   }
} 


