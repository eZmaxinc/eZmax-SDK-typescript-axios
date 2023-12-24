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
import { MultilingualEzsignsigningreasonDescription } from './multilingual-ezsignsigningreason-description';

/**
 * A Ezsignsigningreason Object
 * @export
 * @interface EzsignsigningreasonRequest
 */
export interface EzsignsigningreasonRequest {
    /**
     * The unique ID of the Ezsignsigningreason
     * @type {number}
     * @memberof EzsignsigningreasonRequest
     */
    'pkiEzsignsigningreasonID'?: number;
    /**
     * 
     * @type {MultilingualEzsignsigningreasonDescription}
     * @memberof EzsignsigningreasonRequest
     */
    'objEzsignsigningreasonDescription': MultilingualEzsignsigningreasonDescription;
    /**
     * Whether the ezsignsigningreason is active or not
     * @type {boolean}
     * @memberof EzsignsigningreasonRequest
     */
    'bEzsignsigningreasonIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualEzsignsigningreasonDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualEzsignsigningreasonDescription } from './'

/**
 * @export 
 * A EzsignsigningreasonRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsigningreasonRequest
 */
export class DataObjectEzsignsigningreasonRequest {
   pkiEzsignsigningreasonID?:number = undefined
   objEzsignsigningreasonDescription:MultilingualEzsignsigningreasonDescription = new DataObjectMultilingualEzsignsigningreasonDescription()
   bEzsignsigningreasonIsactive:boolean = false
}

/**
 * @export 
 * A EzsignsigningreasonRequest Validation Object
 * @class ValidationObjectEzsignsigningreasonRequest
 */
export class ValidationObjectEzsignsigningreasonRequest {
   pkiEzsignsigningreasonID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   objEzsignsigningreasonDescription = new ValidationObjectMultilingualEzsignsigningreasonDescription()
   bEzsignsigningreasonIsactive = {
      type: 'boolean',
      required: true
   }
} 


