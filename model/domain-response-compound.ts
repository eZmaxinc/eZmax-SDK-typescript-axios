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
import type { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import type { DomainResponse } from './domain-response';

/**
 * @type DomainResponseCompound
 * A Domain Object
 * @export
 */
/*export type DomainResponseCompound = DomainResponse;*/
export interface DomainResponseCompound {
    /**
     * 
     * @type {Array<CustomDnsrecordResponse>}
     * @memberof DomainResponseCompound
     */
    a_objDnsrecord:Array<CustomDnsrecordResponse> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DomainResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDomainResponseCompound
 */
export class DataObjectDomainResponseCompound {
    a_objDnsrecord:Array<CustomDnsrecordResponse> = []
}

/**
 * @export 
 * A DomainResponseCompound Validation Object
 * @class ValidationObjectDomainResponseCompound
 */
export class ValidationObjectDomainResponseCompound {
   a_objDnsrecord = {
      type: 'array',
      required: true
   }
} 


