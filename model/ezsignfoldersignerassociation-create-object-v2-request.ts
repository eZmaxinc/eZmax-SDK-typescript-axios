/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationRequestCompound } from './ezsignfoldersignerassociation-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for POST /2/object/ezsignfoldersignerassociation
 * @export
 * @interface EzsignfoldersignerassociationCreateObjectV2Request
 */
export interface EzsignfoldersignerassociationCreateObjectV2Request {
    /**
     * 
     * @type {Array<EzsignfoldersignerassociationRequestCompound>}
     * @memberof EzsignfoldersignerassociationCreateObjectV2Request
     */
    'a_objEzsignfoldersignerassociation': Array<EzsignfoldersignerassociationRequestCompound>;
}
/**
 * A EzsignfoldersignerassociationCreateObjectV2Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldersignerassociationCreateObjectV2Request
 */
export class DefaultObjectEzsignfoldersignerassociationCreateObjectV2Request extends DefaultObject {
   a_objEzsignfoldersignerassociation:Array<EzsignfoldersignerassociationRequestCompound> = []
}


