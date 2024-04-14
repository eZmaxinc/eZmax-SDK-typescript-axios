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
 * @interface EzsignsigningreasonResponse
 */
export interface EzsignsigningreasonResponse {
    /**
     * The unique ID of the Ezsignsigningreason
     * @type {number}
     * @memberof EzsignsigningreasonResponse
     */
    /*'pkiEzsignsigningreasonID': number;*/
    'pkiEzsignsigningreasonID': number;
    /**
     * 
     * @type {MultilingualEzsignsigningreasonDescription}
     * @memberof EzsignsigningreasonResponse
     */
    /*'objEzsignsigningreasonDescription': MultilingualEzsignsigningreasonDescription;*/
    'objEzsignsigningreasonDescription': MultilingualEzsignsigningreasonDescription;
    /**
     * Whether the ezsignsigningreason is active or not
     * @type {boolean}
     * @memberof EzsignsigningreasonResponse
     */
    /*'bEzsignsigningreasonIsactive': boolean;*/
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
 * A EzsignsigningreasonResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsigningreasonResponse
 */
export class DataObjectEzsignsigningreasonResponse {
   pkiEzsignsigningreasonID:number = 0
   objEzsignsigningreasonDescription:MultilingualEzsignsigningreasonDescription = new DataObjectMultilingualEzsignsigningreasonDescription()
   bEzsignsigningreasonIsactive:boolean = false
}

/**
 * @export 
 * A EzsignsigningreasonResponse Validation Object
 * @class ValidationObjectEzsignsigningreasonResponse
 */
export class ValidationObjectEzsignsigningreasonResponse {
   pkiEzsignsigningreasonID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   objEzsignsigningreasonDescription = new ValidationObjectMultilingualEzsignsigningreasonDescription()
   bEzsignsigningreasonIsactive = {
      type: 'boolean',
      required: true
   }
} 


