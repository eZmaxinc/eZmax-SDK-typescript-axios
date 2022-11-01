/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupRequestCompound } from './ezsignformfieldgroup-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for PUT /1/object/ezsignformfieldgroup/{pkiEzsignfoldersignerassociationID}
 * @export
 * @interface EzsignformfieldgroupEditObjectV1Request
 */
export interface EzsignformfieldgroupEditObjectV1Request {
    /**
     * 
     * @type {EzsignformfieldgroupRequestCompound}
     * @memberof EzsignformfieldgroupEditObjectV1Request
     */
    'objEzsignformfieldgroup': EzsignformfieldgroupRequestCompound;
}
/**
 * A EzsignformfieldgroupEditObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignformfieldgroupEditObjectV1Request
 */
export class DefaultObjectEzsignformfieldgroupEditObjectV1Request extends DefaultObject {
   objEzsignformfieldgroup:Partial<EzsignformfieldgroupRequestCompound> = {}
}


