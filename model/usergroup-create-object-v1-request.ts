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
import type { UsergroupRequestCompound } from './usergroup-request-compound';

/**
 * Request for POST /1/object/usergroup
 * @export
 * @interface UsergroupCreateObjectV1Request
 */
export interface UsergroupCreateObjectV1Request {
    /**
     * 
     * @type {Array<UsergroupRequestCompound>}
     * @memberof UsergroupCreateObjectV1Request
     */
    /*'a_objUsergroup': Array<UsergroupRequestCompound>;*/
    'a_objUsergroup': Array<UsergroupRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupCreateObjectV1Request
 */
export class DataObjectUsergroupCreateObjectV1Request {
   a_objUsergroup:Array<UsergroupRequestCompound> = []
}

/**
 * @export 
 * A UsergroupCreateObjectV1Request Validation Object
 * @class ValidationObjectUsergroupCreateObjectV1Request
 */
export class ValidationObjectUsergroupCreateObjectV1Request {
   a_objUsergroup = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


