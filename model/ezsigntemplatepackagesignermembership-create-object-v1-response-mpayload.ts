/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Payload for POST /1/object/ezsigntemplatepackagesignermembership
 * @export
 * @interface EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload
 */
export interface EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload
     */
    'a_pkiEzsigntemplatepackagesignermembershipID': Array<number>;
}
/**
 * A EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload extends DefaultObject {
   a_pkiEzsigntemplatepackagesignermembershipID:Array<number> = []
}


