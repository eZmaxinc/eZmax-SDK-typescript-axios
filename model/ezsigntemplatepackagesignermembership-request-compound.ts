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


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignermembershipRequest } from './ezsigntemplatepackagesignermembership-request';

/**
 * @type EzsigntemplatepackagesignermembershipRequestCompound
 * A Ezsigntemplatepackagesignermembership Object and children
 * @export
 */
export type EzsigntemplatepackagesignermembershipRequestCompound = EzsigntemplatepackagesignermembershipRequest;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignermembershipRequestCompound
 */
export class DataObjectEzsigntemplatepackagesignermembershipRequestCompound {
   pkiEzsigntemplatepackagesignermembershipID?:number = undefined
   fkiEzsigntemplatepackagemembershipID:number = 0
   fkiEzsigntemplatepackagesignerID:number = 0
   fkiEzsigntemplatesignerID:number = 0
   iEzsigntemplatepackagesignermembershipCopy?:number = undefined
}

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipRequestCompound Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignermembershipRequestCompound
 */
export class ValidationObjectEzsigntemplatepackagesignermembershipRequestCompound {
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


