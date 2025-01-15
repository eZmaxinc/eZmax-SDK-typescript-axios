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
import type { EzsignsignergroupRequestCompound } from './ezsignsignergroup-request-compound';

/**
 * Request for POST /1/object/ezsignsignergroup
 * @export
 * @interface EzsignsignergroupCreateObjectV1Request
 */
export interface EzsignsignergroupCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsignsignergroupRequestCompound>}
     * @memberof EzsignsignergroupCreateObjectV1Request
     */
    /*'a_objEzsignsignergroup': Array<EzsignsignergroupRequestCompound>;*/
    'a_objEzsignsignergroup': Array<EzsignsignergroupRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignergroupCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupCreateObjectV1Request
 */
export class DataObjectEzsignsignergroupCreateObjectV1Request {
   a_objEzsignsignergroup:Array<EzsignsignergroupRequestCompound> = []
}

/**
 * @export 
 * A EzsignsignergroupCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsignsignergroupCreateObjectV1Request
 */
export class ValidationObjectEzsignsignergroupCreateObjectV1Request {
   a_objEzsignsignergroup = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


