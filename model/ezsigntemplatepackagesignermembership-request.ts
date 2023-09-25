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
 * A Ezsigntemplatepackagesignermembership Object
 * @export
 * @interface EzsigntemplatepackagesignermembershipRequest
 */
export interface EzsigntemplatepackagesignermembershipRequest {
    /**
     * The unique ID of the Ezsigntemplatepackagesignermembership
     * @type {number}
     * @memberof EzsigntemplatepackagesignermembershipRequest
     */
    'pkiEzsigntemplatepackagesignermembershipID'?: number;
    /**
     * The unique ID of the Ezsigntemplatepackagemembership
     * @type {number}
     * @memberof EzsigntemplatepackagesignermembershipRequest
     */
    'fkiEzsigntemplatepackagemembershipID': number;
    /**
     * The unique ID of the Ezsigntemplatepackagesigner
     * @type {number}
     * @memberof EzsigntemplatepackagesignermembershipRequest
     */
    'fkiEzsigntemplatepackagesignerID': number;
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatepackagesignermembershipRequest
     */
    'fkiEzsigntemplatesignerID': number;
    /**
     * The Copy number in case of multiple copies.
     * @type {number}
     * @memberof EzsigntemplatepackagesignermembershipRequest
     */
    'iEzsigntemplatepackagesignermembershipCopy'?: number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignermembershipRequest
 */
export class DataObjectEzsigntemplatepackagesignermembershipRequest {
   pkiEzsigntemplatepackagesignermembershipID?:number = undefined
   fkiEzsigntemplatepackagemembershipID:number = 0
   fkiEzsigntemplatepackagesignerID:number = 0
   fkiEzsigntemplatesignerID:number = 0
   iEzsigntemplatepackagesignermembershipCopy?:number = undefined
}

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipRequest Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignermembershipRequest
 */
export class ValidationObjectEzsigntemplatepackagesignermembershipRequest {
   pkiEzsigntemplatepackagesignermembershipID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplatepackagemembershipID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatepackagesignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatesignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatepackagesignermembershipCopy = {
      type: 'integer',
      minimum: 1,
      required: false
   }
} 


