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
    /*'a_pkiEzsigntemplatepackagesignermembershipID': Array<number>;*/
    'a_pkiEzsigntemplatepackagesignermembershipID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload
 */
export class DataObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload {
   a_pkiEzsigntemplatepackagesignermembershipID:Array<number> = []
}

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload {
   a_pkiEzsigntemplatepackagesignermembershipID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


