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



/**
 * Payload for POST /2/object/ezsigntemplate
 * @export
 * @interface EzsigntemplateCreateObjectV2ResponseMPayload
 */
export interface EzsigntemplateCreateObjectV2ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsigntemplateCreateObjectV2ResponseMPayload
     */
    /*'a_pkiEzsigntemplateID': Array<number>;*/
    'a_pkiEzsigntemplateID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateCreateObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateCreateObjectV2ResponseMPayload
 */
export class DataObjectEzsigntemplateCreateObjectV2ResponseMPayload {
   a_pkiEzsigntemplateID:Array<number> = []
}

/**
 * @export 
 * A EzsigntemplateCreateObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplateCreateObjectV2ResponseMPayload
 */
export class ValidationObjectEzsigntemplateCreateObjectV2ResponseMPayload {
   a_pkiEzsigntemplateID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


