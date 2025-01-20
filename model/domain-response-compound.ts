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
     * The unique ID of the Domain
     * @type {number}
     * @memberof DomainResponseCompound
     */
    pkiDomainID:number 
    /**
     * The name of the Domain
     * @type {string}
     * @memberof DomainResponseCompound
     */
    sDomainName:string 
    /**
     * Whether the DKIM is valid or not
     * @type {boolean}
     * @memberof DomainResponseCompound
     */
    bDomainValiddkim:boolean 
    /**
     * Whether the mail from is valid or not
     * @type {boolean}
     * @memberof DomainResponseCompound
     */
    bDomainValidmailfrom:boolean 
    /**
     * Whether the customer has access to it or not
     * @type {boolean}
     * @memberof DomainResponseCompound
     */
    bDomainValidcustomer:boolean 
    /**
     * 
     * @type {CommonAudit}
     * @memberof DomainResponseCompound
     */
    objAudit:CommonAudit 
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
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A DomainResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDomainResponseCompound
 */
export class DataObjectDomainResponseCompound {
    pkiDomainID:number = 0
    sDomainName:string = ''
    bDomainValiddkim:boolean = false
    bDomainValidmailfrom:boolean = false
    bDomainValidcustomer:boolean = false
    objAudit:CommonAudit = new DataObjectCommonAudit()
    a_objDnsrecord:Array<CustomDnsrecordResponse> = []
}

/**
 * @export 
 * A DomainResponseCompound Validation Object
 * @class ValidationObjectDomainResponseCompound
 */
export class ValidationObjectDomainResponseCompound {
   pkiDomainID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sDomainName = {
      type: 'string',
      pattern: /^(?=.{4,75}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$/,
      required: true
   }
   bDomainValiddkim = {
      type: 'boolean',
      required: true
   }
   bDomainValidmailfrom = {
      type: 'boolean',
      required: true
   }
   bDomainValidcustomer = {
      type: 'boolean',
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
   a_objDnsrecord = {
      type: 'array',
      required: true
   }
} 


