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


// May contain unused imports in some cases
// @ts-ignore
import { FieldESystemconfigurationEzsign } from './field-esystemconfiguration-ezsign';
// May contain unused imports in some cases
// @ts-ignore
import { FieldESystemconfigurationLanguage1 } from './field-esystemconfiguration-language1';
// May contain unused imports in some cases
// @ts-ignore
import { FieldESystemconfigurationLanguage2 } from './field-esystemconfiguration-language2';
// May contain unused imports in some cases
// @ts-ignore
import { FieldESystemconfigurationNewexternaluseraction } from './field-esystemconfiguration-newexternaluseraction';

/**
 * A Systemconfiguration Object
 * @export
 * @interface SystemconfigurationRequest
 */
export interface SystemconfigurationRequest {
    /**
     * The unique ID of the Systemconfiguration
     * @type {number}
     * @memberof SystemconfigurationRequest
     */
    'pkiSystemconfigurationID'?: number;
    /**
     * 
     * @type {FieldESystemconfigurationNewexternaluseraction}
     * @memberof SystemconfigurationRequest
     */
    'eSystemconfigurationNewexternaluseraction': FieldESystemconfigurationNewexternaluseraction;
    /**
     * 
     * @type {FieldESystemconfigurationLanguage1}
     * @memberof SystemconfigurationRequest
     */
    'eSystemconfigurationLanguage1': FieldESystemconfigurationLanguage1;
    /**
     * 
     * @type {FieldESystemconfigurationLanguage2}
     * @memberof SystemconfigurationRequest
     */
    'eSystemconfigurationLanguage2': FieldESystemconfigurationLanguage2;
    /**
     * 
     * @type {FieldESystemconfigurationEzsign}
     * @memberof SystemconfigurationRequest
     */
    'eSystemconfigurationEzsign'?: FieldESystemconfigurationEzsign;
    /**
     * Whether if we allow the creation of personal files in eZsign
     * @type {boolean}
     * @memberof SystemconfigurationRequest
     */
    'bSystemconfigurationEzsignpersonnal': boolean;
    /**
     * Whether if we allow SSPR
     * @type {boolean}
     * @memberof SystemconfigurationRequest
     */
    'bSystemconfigurationSspr': boolean;
    /**
     * The start date where the system will be in read only
     * @type {string}
     * @memberof SystemconfigurationRequest
     */
    'dtSystemconfigurationReadonlyexpirationstart'?: string;
    /**
     * The end date where the system will be in read only
     * @type {string}
     * @memberof SystemconfigurationRequest
     */
    'dtSystemconfigurationReadonlyexpirationend'?: string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A SystemconfigurationRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSystemconfigurationRequest
 */
export class DataObjectSystemconfigurationRequest {
   pkiSystemconfigurationID?:number = undefined
   eSystemconfigurationNewexternaluseraction:FieldESystemconfigurationNewexternaluseraction = 'Stage'
   eSystemconfigurationLanguage1:FieldESystemconfigurationLanguage1 = 'fr_QC'
   eSystemconfigurationLanguage2:FieldESystemconfigurationLanguage2 = 'en_CA'
   eSystemconfigurationEzsign?:FieldESystemconfigurationEzsign = undefined
   bSystemconfigurationEzsignpersonnal:boolean = false
   bSystemconfigurationSspr:boolean = false
   dtSystemconfigurationReadonlyexpirationstart?:string = undefined
   dtSystemconfigurationReadonlyexpirationend?:string = undefined
}

/**
 * @export 
 * A SystemconfigurationRequest Validation Object
 * @class ValidationObjectSystemconfigurationRequest
 */
export class ValidationObjectSystemconfigurationRequest {
   pkiSystemconfigurationID = {
      type: 'integer',
      minimum: 1,
      maximum: 1,
      required: false
   }
   eSystemconfigurationNewexternaluseraction = {
      type: 'enum',
      allowableValues: ['Stage','AutoCreate'],
      required: true
   }
   eSystemconfigurationLanguage1 = {
      type: 'enum',
      allowableValues: ['fr_QC'],
      required: true
   }
   eSystemconfigurationLanguage2 = {
      type: 'enum',
      allowableValues: ['en_CA','en_QC','en_US'],
      required: true
   }
   eSystemconfigurationEzsign = {
      type: 'enum',
      allowableValues: ['No','Yes'],
      required: false
   }
   bSystemconfigurationEzsignpersonnal = {
      type: 'boolean',
      required: true
   }
   bSystemconfigurationSspr = {
      type: 'boolean',
      required: true
   }
   dtSystemconfigurationReadonlyexpirationstart = {
      type: 'string',
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/',
      required: false
   }
   dtSystemconfigurationReadonlyexpirationend = {
      type: 'string',
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/',
      required: false
   }
} 


