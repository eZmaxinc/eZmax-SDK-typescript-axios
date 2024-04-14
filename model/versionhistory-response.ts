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
import { FieldEVersionhistoryType } from './field-eversionhistory-type';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEVersionhistoryUsertype } from './field-eversionhistory-usertype';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualVersionhistoryDetail } from './multilingual-versionhistory-detail';

/**
 * A Versionhistory Object
 * @export
 * @interface VersionhistoryResponse
 */
export interface VersionhistoryResponse {
    /**
     * The unique ID of the Versionhistory
     * @type {number}
     * @memberof VersionhistoryResponse
     */
    /*'pkiVersionhistoryID': number;*/
    'pkiVersionhistoryID': number;
    /**
     * The unique ID of the Module
     * @type {number}
     * @memberof VersionhistoryResponse
     */
    /*'fkiModuleID'?: number;*/
    'fkiModuleID'?: number;
    /**
     * The unique ID of the Modulesection
     * @type {number}
     * @memberof VersionhistoryResponse
     */
    /*'fkiModulesectionID'?: number;*/
    'fkiModulesectionID'?: number;
    /**
     * The Name of the Module in the language of the requester
     * @type {string}
     * @memberof VersionhistoryResponse
     */
    /*'sModuleNameX'?: string;*/
    'sModuleNameX'?: string;
    /**
     * The Name of the Modulesection in the language of the requester
     * @type {string}
     * @memberof VersionhistoryResponse
     */
    /*'sModulesectionNameX'?: string;*/
    'sModulesectionNameX'?: string;
    /**
     * 
     * @type {FieldEVersionhistoryUsertype}
     * @memberof VersionhistoryResponse
     */
    /*'eVersionhistoryUsertype'?: FieldEVersionhistoryUsertype;*/
    'eVersionhistoryUsertype'?: FieldEVersionhistoryUsertype;
    /**
     * 
     * @type {MultilingualVersionhistoryDetail}
     * @memberof VersionhistoryResponse
     */
    /*'objVersionhistoryDetail': MultilingualVersionhistoryDetail;*/
    'objVersionhistoryDetail': MultilingualVersionhistoryDetail;
    /**
     * The date  at which the Versionhistory was published or should be published
     * @type {string}
     * @memberof VersionhistoryResponse
     */
    /*'dtVersionhistoryDate': string;*/
    'dtVersionhistoryDate': string;
    /**
     * The date  at which the Versionhistory will no longer be visible
     * @type {string}
     * @memberof VersionhistoryResponse
     */
    /*'dtVersionhistoryDateend'?: string;*/
    'dtVersionhistoryDateend'?: string;
    /**
     * 
     * @type {FieldEVersionhistoryType}
     * @memberof VersionhistoryResponse
     */
    /*'eVersionhistoryType': FieldEVersionhistoryType;*/
    'eVersionhistoryType': FieldEVersionhistoryType;
    /**
     * Whether the Versionhistory is published or still a draft
     * @type {boolean}
     * @memberof VersionhistoryResponse
     */
    /*'bVersionhistoryDraft': boolean;*/
    'bVersionhistoryDraft': boolean;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualVersionhistoryDetail } from './'
// @ts-ignore
import { ValidationObjectMultilingualVersionhistoryDetail } from './'

/**
 * @export 
 * A VersionhistoryResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVersionhistoryResponse
 */
export class DataObjectVersionhistoryResponse {
   pkiVersionhistoryID:number = 0
   fkiModuleID?:number = undefined
   fkiModulesectionID?:number = undefined
   sModuleNameX?:string = undefined
   sModulesectionNameX?:string = undefined
   eVersionhistoryUsertype?:FieldEVersionhistoryUsertype = undefined
   objVersionhistoryDetail:MultilingualVersionhistoryDetail = new DataObjectMultilingualVersionhistoryDetail()
   dtVersionhistoryDate:string = ''
   dtVersionhistoryDateend?:string = undefined
   eVersionhistoryType:FieldEVersionhistoryType = 'AgentBroker'
   bVersionhistoryDraft:boolean = false
}

/**
 * @export 
 * A VersionhistoryResponse Validation Object
 * @class ValidationObjectVersionhistoryResponse
 */
export class ValidationObjectVersionhistoryResponse {
   pkiVersionhistoryID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiModuleID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiModulesectionID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sModuleNameX = {
      type: 'string',
      required: false
   }
   sModulesectionNameX = {
      type: 'string',
      required: false
   }
   eVersionhistoryUsertype = {
      type: 'enum',
      allowableValues: ['','AgentBroker','EzsignUser','Normal'],
      required: false
   }
   objVersionhistoryDetail = new ValidationObjectMultilingualVersionhistoryDetail()
   dtVersionhistoryDate = {
      type: 'string',
      required: true
   }
   dtVersionhistoryDateend = {
      type: 'string',
      required: false
   }
   eVersionhistoryType = {
      type: 'enum',
      allowableValues: ['AgentBroker','NewFeature','Correction','Modification','ImportantMessage'],
      required: true
   }
   bVersionhistoryDraft = {
      type: 'boolean',
      required: true
   }
} 


