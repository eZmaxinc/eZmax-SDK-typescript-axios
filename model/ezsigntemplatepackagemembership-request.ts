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
 * A Ezsigntemplatepackagemembership Object
 * @export
 * @interface EzsigntemplatepackagemembershipRequest
 */
export interface EzsigntemplatepackagemembershipRequest {
    /**
     * The unique ID of the Ezsigntemplatepackagemembership
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipRequest
     */
    'pkiEzsigntemplatepackagemembershipID'?: number;
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipRequest
     */
    'fkiEzsigntemplatepackageID': number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipRequest
     */
    'fkiEzsigntemplateID': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagemembershipRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagemembershipRequest
 */
export class DataObjectEzsigntemplatepackagemembershipRequest {
   pkiEzsigntemplatepackagemembershipID?:number = undefined
   fkiEzsigntemplatepackageID:number = 0
   fkiEzsigntemplateID:number = 0
}

/**
 * @export 
 * A EzsigntemplatepackagemembershipRequest Validation Object
 * @class ValidationObjectEzsigntemplatepackagemembershipRequest
 */
export class ValidationObjectEzsigntemplatepackagemembershipRequest {
   pkiEzsigntemplatepackagemembershipID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
} 


