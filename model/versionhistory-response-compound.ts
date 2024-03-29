/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
// May contain unused imports in some cases
// @ts-ignore
import { VersionhistoryResponse } from './versionhistory-response';

/**
 * @type VersionhistoryResponseCompound
 * A Versionhistory Object
 * @export
 */
export type VersionhistoryResponseCompound = VersionhistoryResponse;



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
 * A VersionhistoryResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVersionhistoryResponseCompound
 */
export class DataObjectVersionhistoryResponseCompound {
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
 * A VersionhistoryResponseCompound Validation Object
 * @class ValidationObjectVersionhistoryResponseCompound
 */
export class ValidationObjectVersionhistoryResponseCompound {
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


