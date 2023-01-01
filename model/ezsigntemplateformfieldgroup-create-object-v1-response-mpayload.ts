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



import { DefaultObject } from '../base'

/**
 * Payload for POST /1/object/ezsigntemplateformfieldgroup
 * @export
 * @interface EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload
 */
export interface EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload
     */
    'a_pkiEzsigntemplateformfieldgroupID': Array<number>;
}
/**
 * A EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload extends DefaultObject {
   a_pkiEzsigntemplateformfieldgroupID:Array<number> = []
}


